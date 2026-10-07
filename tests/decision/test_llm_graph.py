"""LangGraph 5-node state machine tests (fallback path, LLM disabled)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from services.decision.guardrails import FriendlyZone
from services.decision.llm_graph import run_graph
from services.decision.roe import load_roe
from services.decision.schemas import Action

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
async def test_graph_runs_without_llm():
    rules = load_roe(CONFIG_PATH)
    decision = await run_graph(_track(), rules)
    assert decision is not None
    assert decision.track_id == "t-graph"
    # LLM disabled -> rule engine decision
    assert decision.source.value in ("rule_engine", "llm_advisor")


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
    # HIGH inside zone -> can be HANDOFF but friendly zone makes it ALERT
    assert decision.action != Action.ENGAGE
    # friendly-zone guardrail tetiklendi
    assert any("friendly-zone" in g for g in decision.guardrails_triggered)


@pytest.mark.asyncio
async def test_graph_audit_trail_present():
    rules = load_roe(CONFIG_PATH)
    decision = await run_graph(_track(), rules)
    assert decision.timestamp_iso
    assert isinstance(decision.guardrails_triggered, list)


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
