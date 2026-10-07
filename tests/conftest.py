"""
tests/conftest.py — Shared pytest fixtures for the Kyvern test suite.

Covers:
  * Decision engine  — clean in-memory state (ROERule list + bare track dict)
  * pytest-asyncio   — async_mode = "auto" is declared in pyproject.toml;
                       this file keeps the async event-loop fixture explicit for
                       tests that need manual control.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from services.decision.schemas import Action, ROERule, ThreatLevel

# ══════════════════════════════════════════════════════════════════════════════
# Isolation from the developer's real home directory
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def isolated_home(tmp_path_factory, monkeypatch) -> Path:
    """Point Path.home() at a fresh directory for every test.

    run_graph() and ChainWriter.open() create the signing key under ~/.kyvern and
    append to ~/.kyvern/chain.jsonl; no test may touch the developer's real ones.
    """
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    monkeypatch.delenv("KYVERN_CHAIN_PATH", raising=False)
    return home


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
