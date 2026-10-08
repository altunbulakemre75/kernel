"""LangGraph 5-node state machine tests.

The LLM is off unless a test turns it on with a fake query_llm; no test calls a real LLM.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from services.decision import llm_graph
from services.decision.guardrails import FriendlyZone
from services.decision.llm_client import LLMResponse
from services.decision.llm_graph import _reconcile_action, run_graph
from services.decision.roe import load_roe
from services.decision.schemas import Action, DecisionSource

CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "policies" / "default.yaml"


def _track(**overrides) -> dict:
    base = {
        "track_id": "t-graph",
        "latitude": 40.0, "longitude": 33.0,   # outside zone
        "altitude": 100.0,
        "confidence": 0.9,
        "hits": 10,
        "vx": 0.0, "vy": 0.0, "vz": 0.0,
        "sources": ["camera"],
        "uas_id": None,
        "class_name": None,
        "x": 0.0, "y": 0.0, "z": 100.0,
    }
    base.update(overrides)
    return base


@pytest.mark.asyncio
async def test_graph_runs_without_llm(monkeypatch):
    _llm_off(monkeypatch)
    rules = load_roe(CONFIG_PATH)
    decision = await run_graph(_track(), rules)
    assert decision.track_id == "t-graph"
    assert decision.source == DecisionSource.RULE_ENGINE
    assert decision.llm_raw_response is None


@pytest.mark.asyncio
async def test_graph_triggers_guardrail_in_friendly_zone():
    rules = load_roe(CONFIG_PATH)
    zones = [FriendlyZone(
        zone_id="OP", name="ops",
        center_lat=39.9334, center_lon=32.8597, radius_m=500,
    )]
    track = _track(latitude=39.9335, longitude=32.8598, confidence=0.9)  # inside zone
    decision = await run_graph(track, rules, friendly_zones=zones,
                               inside_protected_zone=True)
    # HIGH inside the zone would be HANDOFF; the friendly-zone guardrail caps it at ALERT.
    assert decision.action == Action.ALERT
    assert decision.guardrails_triggered == ["friendly-zone-OP"]


@pytest.mark.asyncio
async def test_graph_audit_trail_present():
    rules = load_roe(CONFIG_PATH)
    decision = await run_graph(_track(), rules)
    assert datetime.fromisoformat(decision.timestamp_iso).utcoffset().total_seconds() == 0
    assert decision.roe_reference in {r.rule_id for r in rules}
    assert decision.reasoning


@pytest.mark.asyncio
async def test_run_graph_appends_each_decision_to_the_chain(tmp_path):
    chain = tmp_path / "chain.jsonl"
    rules = load_roe(CONFIG_PATH)
    d1 = await run_graph(_track(), rules, chain_path=chain)
    d2 = await run_graph(_track(track_id="t-2"), rules, chain_path=chain)
    entries = [json.loads(line) for line in chain.read_text(encoding="utf-8").splitlines()]
    assert [e["track_id"] for e in entries] == ["t-graph", "t-2"]
    assert [e["chain_index"] for e in entries] == [0, 1]
    assert d2.prev_hash == d1.payload_hash == entries[0]["payload_hash"]
    assert d1.key_id == entries[0]["key_id"]


@pytest.mark.asyncio
async def test_run_graph_defaults_to_the_kyvern_home_chain(isolated_home):
    await run_graph(_track(), load_roe(CONFIG_PATH))
    chain = isolated_home / ".kyvern" / "chain.jsonl"
    assert len(chain.read_text(encoding="utf-8").splitlines()) == 1


@pytest.mark.asyncio
async def test_run_graph_raises_when_the_decision_cannot_be_recorded(tmp_path):
    from services.decision.chain_writer import AuditWriteError

    chain = tmp_path / "chain.jsonl"
    chain.mkdir()  # a directory where the chain file should be: appending fails
    with pytest.raises(AuditWriteError):
        await run_graph(_track(), load_roe(CONFIG_PATH), chain_path=chain)


# ── LLM reconciliation (safety critical) ─────────────────────────────────────
# run_graph() merges the LLM's answer with _reconcile_action: the LLM may only raise
# the rule engine's action, never lower it, and never to ENGAGE.

def _llm(action: str) -> LLMResponse:
    return LLMResponse(
        action=action, threat_level="high", confidence=0.9, reasoning="fake advisor",
        roe_reference=None, raw={"action": action}, provider="fake", model="fake-1",
    )


def _llm_off(monkeypatch):
    monkeypatch.delenv("KYVERN_DECISION_LLM_ENABLED", raising=False)


def _llm_answers(monkeypatch, action: str):
    """Turn the LLM on, answering every prompt with `action`."""
    async def fake_query_llm(prompt):
        return _llm(action)

    monkeypatch.setenv("KYVERN_DECISION_LLM_ENABLED", "true")
    monkeypatch.setattr(llm_graph, "query_llm", fake_query_llm)


@pytest.mark.parametrize(("rule", "llm", "expected"), [
    (Action.ALERT, None, Action.ALERT),             # no LLM answer: the rule stands
    (Action.LOG, "alert", Action.ALERT),            # the LLM may raise the action
    (Action.ALERT, "handoff", Action.HANDOFF),
    (Action.HANDOFF, "log", Action.HANDOFF),        # ... but never lower it
    (Action.ENGAGE, "log", Action.ENGAGE),
    (Action.ALERT, "engage", Action.ALERT),         # ... and never to ENGAGE
    (Action.LOG, "engage", Action.LOG),
    (Action.ALERT, "self-destruct", Action.ALERT),  # an unknown action is ignored
])
def test_reconcile_action(rule, llm, expected):
    assert _reconcile_action(rule, _llm(llm) if llm else None) == expected


@pytest.mark.asyncio
async def test_graph_with_llm_never_engages_and_records_the_llm_answer(monkeypatch, tmp_path):
    rules = load_roe(CONFIG_PATH)
    _llm_off(monkeypatch)
    rule_only = await run_graph(_track(), rules, chain_path=tmp_path / "rule.jsonl")

    _llm_answers(monkeypatch, "engage")
    chain = tmp_path / "chain.jsonl"
    decision = await run_graph(_track(), rules, chain_path=chain)

    assert decision.action == rule_only.action
    assert (decision.llm_provider, decision.llm_model) == ("fake", "fake-1")
    assert decision.llm_raw_response == {"action": "engage"}
    assert "LLM(fake): fake advisor" in decision.reasoning
    entry = json.loads(chain.read_text(encoding="utf-8").splitlines()[0])
    assert entry["llm_raw_response"] == {"action": "engage"}


@pytest.mark.asyncio
async def test_graph_with_llm_can_raise_the_action(monkeypatch):
    rules = load_roe(CONFIG_PATH)
    _llm_off(monkeypatch)
    rule_only = await run_graph(_track(), rules)
    assert rule_only.action in (Action.LOG, Action.ALERT)  # precondition: HANDOFF is a raise

    _llm_answers(monkeypatch, "handoff")
    assert (await run_graph(_track(), rules)).action == Action.HANDOFF


@pytest.mark.asyncio
async def test_guardrails_still_cap_an_action_the_llm_raised(monkeypatch):
    _llm_answers(monkeypatch, "handoff")
    zones = [FriendlyZone(zone_id="OP", name="ops", center_lat=40.0, center_lon=33.0, radius_m=500)]

    decision = await run_graph(_track(), load_roe(CONFIG_PATH), friendly_zones=zones)
    assert decision.action == Action.ALERT
    assert decision.guardrails_triggered == ["friendly-zone-OP"]


@pytest.mark.asyncio
async def test_decision_source_is_the_llm_only_when_it_changed_the_action(monkeypatch):
    rules = load_roe(CONFIG_PATH)
    _llm_off(monkeypatch)
    rule_only = await run_graph(_track(), rules)

    _llm_answers(monkeypatch, rule_only.action.value)  # the LLM agrees with the rule
    agreed = await run_graph(_track(), rules)
    assert agreed.source == DecisionSource.RULE_ENGINE
    assert agreed.llm_provider == "fake"  # consulted, and recorded as such

    _llm_answers(monkeypatch, "engage")  # ignored
    assert (await run_graph(_track(), rules)).source == DecisionSource.RULE_ENGINE

    _llm_answers(monkeypatch, "handoff")  # raises the rule's action
    assert (await run_graph(_track(), rules)).source == DecisionSource.LLM_ADVISOR


def test_llm_is_enabled_only_by_the_kyvern_variable(monkeypatch):
    _llm_off(monkeypatch)
    monkeypatch.setenv("NIZAM_DECISION_LLM_ENABLED", "true")  # pre-rename name: ignored
    assert not llm_graph._is_llm_enabled()
    monkeypatch.setenv("KYVERN_DECISION_LLM_ENABLED", "true")
    assert llm_graph._is_llm_enabled()
