"""
tests/conftest.py — Shared pytest fixtures for the kernel test suite.

Covers:
  * Decision engine  — clean in-memory state (ROERule list + bare track dict)
  * Fusion engine    — sample Measurement objects representing multi-sensor input
  * pytest-asyncio   — async_mode = "auto" is declared in pyproject.toml;
                       this file keeps the async event-loop fixture explicit for
                       tests that need manual control.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Generator

import pytest

from services.decision.schemas import Action, ROERule, ThreatLevel
from services.fusion.track_manager import TrackManager
from services.schemas.track import Measurement, SensorType


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ══════════════════════════════════════════════════════════════════════════════
# Decision engine fixtures
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def minimal_roe_rules() -> list[ROERule]:
    """Minimal, fully deterministic ROE rule set for unit tests.

    Covers LOW → LOG, MEDIUM → ALERT, HIGH → ALERT (with approval),
    CRITICAL → ENGAGE (operator approval required).  No external files needed.
    """
    return [
        ROERule(
            rule_id="R-LOW",
            description="Low threat — log only",
            when_threat_level=ThreatLevel.LOW,
            requires_operator_approval=False,
            action=Action.LOG,
        ),
        ROERule(
            rule_id="R-MEDIUM",
            description="Medium threat — alert operator",
            when_threat_level=ThreatLevel.MEDIUM,
            requires_operator_approval=False,
            action=Action.ALERT,
        ),
        ROERule(
            rule_id="R-HIGH",
            description="High threat — alert, operator must confirm",
            when_threat_level=ThreatLevel.HIGH,
            requires_operator_approval=True,
            action=Action.ALERT,
        ),
        ROERule(
            rule_id="R-CRITICAL",
            description="Critical threat — engage after operator approval",
            when_threat_level=ThreatLevel.CRITICAL,
            requires_operator_approval=True,
            action=Action.ENGAGE,
        ),
    ]


@pytest.fixture
def clean_track() -> dict:
    """Bare track dict representing a brand-new, unthreatening contact.

    All scoring factors (zone breach, speed, transponder) are at neutral
    defaults so individual tests can flip exactly one flag at a time.
    """
    return {
        "track_id": "T-TEST",
        # Speed below AGGRESSIVE_SPEED_MPS (30 m/s) → no speed flag
        "vx": 10.0,
        "vy": 0.0,
        # Transponder present → no unknown-transponder flag
        "uas_id": "FA123456",
        # Confidence below HIGH_CONFIDENCE_THRESHOLD (0.80) → no confidence flag
        "confidence": 0.50,
    }


@pytest.fixture
def high_threat_track() -> dict:
    """Track with all threat flags set → should score CRITICAL under full rules."""
    return {
        "track_id": "T-HOSTILE",
        "vx": 35.0,   # > 30 m/s → aggressive_speed
        "vy": 0.0,
        # No uas_id → unknown_transponder
        "confidence": 0.92,  # > 0.80 → confidence_exceeds_threshold
    }


# ══════════════════════════════════════════════════════════════════════════════
# Fusion engine fixtures
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def fresh_track_manager() -> Generator[TrackManager, None, None]:
    """A brand-new TrackManager with no prior state.

    Yielded so teardown (clearing internal dicts) is guaranteed even if the
    test fails mid-way.
    """
    manager = TrackManager()
    yield manager
    # Teardown — reset internal track registry
    manager._tracks.clear()  # type: ignore[attr-defined]


@pytest.fixture
def radar_measurement() -> Measurement:
    """Single radar measurement in ENU coordinates (east=200 m, north=500 m)."""
    return Measurement(
        sensor_id="radar-01",
        sensor_type=SensorType.RADAR,
        timestamp_iso=_now_iso(),
        x=200.0,   # east  metres
        y=500.0,   # north metres
        z=120.0,   # alt   metres
        sigma_x=5.0,
        sigma_y=5.0,
        sigma_z=10.0,
        class_name="drone",
        class_conf=0.88,
    )


@pytest.fixture
def rf_odid_measurement() -> Measurement:
    """RF/ODID measurement slightly offset from the radar hit (same drone)."""
    return Measurement(
        sensor_id="rf-01",
        sensor_type=SensorType.RF_ODID,
        timestamp_iso=_now_iso(),
        x=203.0,
        y=497.0,
        z=118.0,
        sigma_x=3.0,
        sigma_y=3.0,
        sigma_z=8.0,
        uas_id="FA-HOSTILE-001",
        rssi_dbm=-72.5,
    )


@pytest.fixture
def camera_measurement() -> Measurement:
    """Camera measurement for the same target (higher position uncertainty)."""
    return Measurement(
        sensor_id="cam-01",
        sensor_type=SensorType.CAMERA,
        timestamp_iso=_now_iso(),
        x=198.0,
        y=505.0,
        z=125.0,
        sigma_x=30.0,
        sigma_y=30.0,
        sigma_z=50.0,
        class_name="drone",
        class_conf=0.75,
    )


@pytest.fixture
def multi_sensor_batch(
    radar_measurement: Measurement,
    rf_odid_measurement: Measurement,
    camera_measurement: Measurement,
) -> list[Measurement]:
    """Combined batch of all three sensor hits for one fusion tick."""
    return [radar_measurement, rf_odid_measurement, camera_measurement]


# ══════════════════════════════════════════════════════════════════════════════
# Async helpers
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def event_loop():
    """Explicit event-loop fixture — use when a test needs a shared loop.

    pytest-asyncio's asyncio_mode = "auto" (set in pyproject.toml) handles
    most cases automatically; override here only when the default loop scope
    causes problems (e.g. tests that share NATS connections).
    """
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()
