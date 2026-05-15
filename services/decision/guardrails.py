"""Decision layer guardrails — run AFTER the LLM or rule engine decision
and downgrade safety violations.

OpenAI Agents guardrail pattern adaptation. Each guardrail:
  - Returns a name + description
  - Inspects the Decision + context
  - If triggered=True, recommends a downgrade (drop to LOG/ALERT)

Rule: guardrails NEVER upgrade, only downgrade or pass.
This ensures a false-positive trigger never produces a dangerous action.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import yaml

from services.autonomy.geofence import NoFlyZone, haversine_m
from services.decision.schemas import Action, Decision

log = logging.getLogger(__name__)

# Severity ordering (for downgrade logic)
_SEVERITY = {Action.LOG: 0, Action.ALERT: 1, Action.HANDOFF: 2, Action.ENGAGE: 3}


@dataclass
class GuardrailResult:
    guardrail_id: str
    triggered: bool
    reason: str = ""
    downgrade_to: Action | None = None


# ── Guardrail 1: Input validation ──────────────────────────────────

def input_track_guardrail(track: dict) -> GuardrailResult:
    """If the track is malformed, do not issue ALERT/ENGAGE — downgrade to LOG.

    - confidence < 0.1 (uncertain anomaly)
    - lat/lon 0/0 or missing (invalid position)
    - hits < 2 (single tick, could be momentary noise)
    """
    conf = float(track.get("confidence", 0.0))
    hits = int(track.get("hits", 0))
    lat = float(track.get("latitude", track.get("x", 0.0)) or 0.0)
    lon = float(track.get("longitude", track.get("y", 0.0)) or 0.0)

    if conf < 0.1:
        return GuardrailResult(
            "input-confidence-low", True,
            f"confidence={conf:.2f} < 0.1 — downgrading to LOG",
            downgrade_to=Action.LOG,
        )
    if hits < 2:
        return GuardrailResult(
            "input-single-tick", True,
            f"hits={hits} — could be momentary noise",
            downgrade_to=Action.LOG,
        )
    if lat == 0.0 and lon == 0.0:
        return GuardrailResult(
            "input-geo-zero", True,
            "lat/lon = 0/0 — GPS invalid",
            downgrade_to=Action.LOG,
        )
    return GuardrailResult("input-track", False)


# ── Guardrail 2: Friendly zone check ──────────────────────────────

@dataclass
class FriendlyZone:
    """Friendly base, own drone flight area, operator position."""
    zone_id: str
    name: str
    center_lat: float
    center_lon: float
    radius_m: float


def _load_friendly_zones_from(path: Path) -> list[FriendlyZone]:
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw = data.get("zones", []) if isinstance(data, dict) else data
    return [FriendlyZone(**z) for z in raw]


DEFAULT_FRIENDLY_ZONES_PATH = Path("config/friendly_zones.yaml")


def friendly_zone_guardrail(
    track: dict, zones: list[FriendlyZone] | None = None,
) -> GuardrailResult:
    """If the track is inside a protected zone, downgrade ENGAGE/HANDOFF → ALERT.

    "No physical action inside a protected area" rule. Protected zones
    must be registered in friendly_zones.yaml.
    """
    if zones is None:
        zones = _load_friendly_zones_from(DEFAULT_FRIENDLY_ZONES_PATH)
    if not zones:
        return GuardrailResult("friendly-zone", False, "no friendly zones configured")

    lat = track.get("latitude")
    lon = track.get("longitude")
    if lat is None or lon is None:
        return GuardrailResult("friendly-zone", False, "no lat/lon")

    for zone in zones:
        dist = haversine_m(float(lat), float(lon), zone.center_lat, zone.center_lon)
        if dist <= zone.radius_m:
            return GuardrailResult(
                f"friendly-zone-{zone.zone_id}", True,
                f"subject in {zone.name} protected zone (dist={dist:.0f}m) — ENGAGE prohibited",
                downgrade_to=Action.ALERT,
            )
    return GuardrailResult("friendly-zone", False)


# ── Guardrail 3: Civilian traffic pattern ──────────────────────────

def civilian_pattern_guardrail(track: dict) -> GuardrailResult:
    """Cancel ENGAGE if a civilian traffic pattern is detected.

    Heuristics:
    - Known ADS-B transponder code present (ICAO / squawk)
    - Speed > 150 m/s (likely fixed-wing aircraft)
    - Altitude > 3000m (typical civilian altitude)
    """
    uas_id = str(track.get("uas_id") or "")
    vx = float(track.get("vx", 0.0))
    vy = float(track.get("vy", 0.0))
    speed = (vx * vx + vy * vy) ** 0.5
    alt = float(track.get("altitude", track.get("z", 0.0)) or 0.0)

    # Known civilian transponder prefixes
    civil_prefixes = ("TC-", "N-", "D-", "G-", "F-")  # TR, US, DE, UK, FR
    if uas_id and any(uas_id.upper().startswith(p) for p in civil_prefixes):
        return GuardrailResult(
            "civilian-transponder", True,
            f"uas_id={uas_id} civilian registration",
            downgrade_to=Action.ALERT,
        )

    if speed > 150.0 and alt > 3000.0:
        return GuardrailResult(
            "civilian-airliner-pattern", True,
            f"speed={speed:.0f}m/s alt={alt:.0f}m — likely civilian aircraft",
            downgrade_to=Action.ALERT,
        )

    return GuardrailResult("civilian-pattern", False)


# ── Orchestrator ───────────────────────────────────────────────────

ALL_GUARDRAILS = [
    input_track_guardrail,
    friendly_zone_guardrail,
    civilian_pattern_guardrail,
]


def apply_guardrails(
    decision: Decision, track: dict,
    friendly_zones: list[FriendlyZone] | None = None,
) -> Decision:
    """Run all guardrails, attach triggered ones to the decision, and apply downgrades.

    Downgrade rule: if a guardrail's downgrade_to has **lower** severity
    than the current action, the downgrade_to becomes the new action.
    Guardrails NEVER upgrade.
    """
    final_action = decision.action
    triggered_ids: list[str] = []
    reasons: list[str] = []

    for guard in ALL_GUARDRAILS:
        if guard is friendly_zone_guardrail:
            result = guard(track, zones=friendly_zones)
        else:
            result = guard(track)
        if not result.triggered:
            continue
        triggered_ids.append(result.guardrail_id)
        reasons.append(result.reason)
        if result.downgrade_to is None:
            continue
        proposed = result.downgrade_to
        if _SEVERITY[proposed] < _SEVERITY[final_action]:
            final_action = proposed

    if not triggered_ids:
        return decision

    # Guardrail explanations in a separate field — main reasoning preserved without truncation
    log.info("guardrails triggered: %s → action %s → %s",
             triggered_ids, decision.action.value, final_action.value)

    return decision.model_copy(update={
        "action": final_action,
        "guardrails_triggered": triggered_ids,
        "guardrail_reasoning": "; ".join(reasons),   # full text, no truncation
        "requires_operator_approval":
            decision.requires_operator_approval or final_action == Action.ENGAGE,
    })
