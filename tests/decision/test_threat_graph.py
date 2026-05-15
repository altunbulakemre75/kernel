"""End-to-end decision graph tests — safety critical."""
from __future__ import annotations

from pathlib import Path

from services.decision.roe import load_roe
from services.decision.schemas import Action, DecisionSource, ThreatLevel
from services.decision.threat_graph import decide


CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "policies" / "default.yaml"


def _track(**overrides) -> dict:
    base = {
        "track_id": "t-demo",
        "confidence": 0.5,
        "vx": 0.0, "vy": 0.0, "vz": 0.0,
    }
    base.update(overrides)
    return base


def test_decision_source_always_rule_engine():
    rules = load_roe(CONFIG_PATH)
    _, decision = decide(_track(), rules)
    assert decision.source == DecisionSource.RULE_ENGINE


def test_benign_track_logged():
    rules = load_roe(CONFIG_PATH)
    _, decision = decide(_track(), rules)
    assert decision.action == Action.LOG
    assert decision.requires_operator_approval is False


def test_high_threat_outside_zone_alerts_without_approval():
    """Spatial threat (inside zone) is required to escalate to CRITICAL;
    outside zone worst case scenario is HIGH -> POL-4 alert."""
    rules = load_roe(CONFIG_PATH)
    track = _track(confidence=1.0, vx=100.0)
    assessment, decision = decide(track, rules, inside_protected_zone=False, heading_toward_zone=True)
    assert assessment.threat_level == ThreatLevel.HIGH  # 0.20+0.15+0.15+0.15 = 0.65
    assert decision.action == Action.ALERT
    assert decision.requires_operator_approval is False
    assert decision.roe_reference == "POL-4"


def test_critical_inside_zone_does_NOT_engage_because_rule_disabled():
    """Most critical test: default ENGAGE rule is disabled -> never engage."""
    rules = load_roe(CONFIG_PATH)
    track = _track(confidence=1.0, vx=100.0)
    _, decision = decide(
        track, rules, inside_protected_zone=True, heading_toward_zone=True
    )
    assert decision.action != Action.ENGAGE, (
        "SECURITY VIOLATION: CRITICAL inside zone escalated to ENGAGE — POL-5 must be disabled"
    )
    # Fallback: no matching rule -> LOG
    assert decision.action == Action.LOG


def test_high_threat_inside_zone_handoff_with_approval():
    rules = load_roe(CONFIG_PATH)
    # score: 0.35 (zone) + 0.15 (unknown) + 0.20 (conf high) = 0.70 → HIGH
    track = _track(confidence=0.9)
    _, decision = decide(
        track, rules, inside_protected_zone=True, heading_toward_zone=False
    )
    assert decision.threat_level == ThreatLevel.HIGH
    assert decision.action == Action.HANDOFF
    assert decision.requires_operator_approval is True
    assert decision.roe_reference == "POL-3"


def test_medium_threat_alerts_without_approval():
    rules = load_roe(CONFIG_PATH)
    # 0.20 (conf) + 0.15 (unknown) = 0.35 → MEDIUM
    track = _track(confidence=0.9)
    _, decision = decide(track, rules, inside_protected_zone=False)
    assert decision.threat_level == ThreatLevel.MEDIUM
    assert decision.action == Action.ALERT
    assert decision.requires_operator_approval is False


def test_decision_has_timestamp_and_track_id():
    rules = load_roe(CONFIG_PATH)
    _, decision = decide(_track(track_id="t-xyz"), rules)
    assert decision.track_id == "t-xyz"
    assert decision.timestamp_iso  # not empty
    assert "T" in decision.timestamp_iso  # ISO format


def test_engage_always_requires_operator_approval_even_if_rule_says_no():
    """Safety check: even if an ENGAGE action is triggered, operator approval is forced."""
    from services.decision.schemas import ROERule

    # Broken rule: ENGAGE but operator_approval=False
    bad_rules = [
        ROERule(
            rule_id="BAD", description="auto-engage (dangerous)",
            when_threat_level=ThreatLevel.CRITICAL,
            requires_operator_approval=False, action=Action.ENGAGE, enabled=True,
        ),
    ]
    track = _track(confidence=1.0, vx=100.0)
    _, decision = decide(track, bad_rules, inside_protected_zone=True, heading_toward_zone=True)
    # Rule triggered ENGAGE but system forced approval
    assert decision.action == Action.ENGAGE
    assert decision.requires_operator_approval is True, (
        "SECURITY VIOLATION: ENGAGE can be executed without operator approval"
    )
