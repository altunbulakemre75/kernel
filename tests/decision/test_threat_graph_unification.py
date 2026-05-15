"""threat_graph.decide + decide_full unification test — single production path."""
from __future__ import annotations

from pathlib import Path

import pytest

from services.decision.guardrails import FriendlyZone
from services.decision.roe import load_roe
from services.decision.schemas import Action
from services.decision.threat_graph import decide, decide_full


CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "policies" / "default.yaml"


def _track(**overrides) -> dict:
    base = {
        "track_id": "t-u",
        "latitude": 40.0, "longitude": 33.0,
        "altitude": 100.0, "confidence": 0.9, "hits": 10,
        "vx": 5.0, "vy": 0.0, "vz": 0.0,
        "x": 0.0, "y": 0.0, "z": 100.0,
        "sources": ["camera"],
    }
    base.update(overrides)
    return base


def test_decide_sync_rule_only_no_llm():
    """decide() does not invoke LLM, rule-only."""
    rules = load_roe(CONFIG_PATH)
    _, decision = decide(_track(), rules)
    assert decision.llm_provider is None
    assert decision.llm_raw_response is None


def test_decide_full_sync_runs_graph():
    """decide_full() runs the LangGraph 5-node pipeline synchronously."""
    rules = load_roe(CONFIG_PATH)
    decision = decide_full(_track(), rules)
    assert decision is not None
    assert decision.track_id == "t-u"
    # LLM disabled (no NIZAM_DECISION_LLM_ENABLED env) -> llm_provider None
    # Guardrails executed -> guardrails_triggered is list


def test_decide_with_guardrails_downgrades_low_conf():
    rules = load_roe(CONFIG_PATH)
    _, decision = decide(
        _track(confidence=0.05, hits=5),
        rules, apply_guards=True,
    )
    # Low confidence guardrail triggered
    assert any("input" in g for g in decision.guardrails_triggered)


def test_decide_full_applies_friendly_zone_guardrail():
    rules = load_roe(CONFIG_PATH)
    zones = [FriendlyZone(
        zone_id="OP", name="ops",
        center_lat=40.0, center_lon=33.0, radius_m=500,
    )]
    track = _track(latitude=40.001, longitude=33.001)  # inside zone
    decision = decide_full(track, rules, friendly_zones=zones,
                           inside_protected_zone=True)
    assert decision.action != Action.ENGAGE


def test_guardrail_reasoning_separate_from_reasoning():
    """Guardrail explanation does not truncate reasoning — separate field."""
    rules = load_roe(CONFIG_PATH)
    _, decision = decide(
        _track(confidence=0.05, hits=1),  # iki guardrail tetikler
        rules, apply_guards=True,
    )
    if decision.guardrails_triggered:
        # guardrail_reasoning populated, reasoning original kept
        assert decision.guardrail_reasoning
        assert "guardrails" not in decision.reasoning  # no longer appended to reasoning
