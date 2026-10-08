"""kyvern.record_decision(): a team's own decisions in the signed chain.

See docs/superpowers/specs/2026-10-08-record-decision-design.md.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from kyvern import RecordedDecision, record_decision
from kyvern.audit import AuditChainStore
from services.decision.audit_chain import (
    append_runtime_event,
    load_or_create_keypair,
    verify_chain,
)
from services.decision.policy_loader import clear_policy_cache, load_policy
from services.decision.roe import load_roe
from services.decision.threat_graph import decide_full
from shared.schemas import RuntimeEvent

REPO_ROOT = Path(__file__).parent.parent
DEFAULT_POLICY = REPO_ROOT / "config" / "policies" / "default.yaml"

SAFETY_POLICY = """\
rules:
  - id: stop-on-obstacle
    when: obstacle_distance_m < 0.5
    action: stop
  - id: slow-near-people
    when: person_distance_m < 2.0
    action: slow
"""


@pytest.fixture
def ws(tmp_path, isolated_home):
    clear_policy_cache()
    policy = tmp_path / "safety_policy.yaml"
    policy.write_text(SAFETY_POLICY, encoding="utf-8")
    return {
        "chain": tmp_path / "chain.jsonl",
        "policy": policy,
        "pub": isolated_home / ".kyvern" / "keys" / "signing.pub",
        "pdf": tmp_path / "report.pdf",
    }


def _stop(ws, **overrides):
    kwargs = {
        "source": "safety_controller",
        "reasoning": "obstacle at 0.4 m, closer than 0.5 m",
        "inputs": {"obstacle_distance_m": 0.4},
        "rule_id": "stop-on-obstacle",
        "policy_path": ws["policy"],
        "chain_path": ws["chain"],
    }
    kwargs.update(overrides)
    return record_decision("stop", **kwargs)


def _entries(ws):
    return [json.loads(line) for line in ws["chain"].read_text(encoding="utf-8").splitlines()]


def _cli(module, *args):
    env = dict(os.environ, PYTHONPATH=str(REPO_ROOT))
    return subprocess.run(
        [sys.executable, "-m", module, *map(str, args)], capture_output=True, text=True, env=env,
    )


# ── recording ─────────────────────────────────────────────────────────────────

def test_record_decision_appends_a_signed_decision(ws):
    decision = _stop(ws)

    assert isinstance(decision, RecordedDecision)
    assert decision.record_type == "decision"
    assert decision.action == "stop"
    assert decision.chain_index == 0
    assert decision.policy_version_id == load_policy(str(ws["policy"])).version_id
    assert datetime.fromisoformat(decision.timestamp_iso).utcoffset().total_seconds() == 0

    (entry,) = _entries(ws)
    assert entry["record_type"] == "decision"
    assert entry["inputs"] == {"obstacle_distance_m": 0.4}
    assert entry["rule_id"] == "stop-on-obstacle"
    assert entry["payload_hash"] == decision.payload_hash
    assert verify_chain(_entries(ws), load_or_create_keypair().public_key()) == (True, None)


def test_recorded_decisions_share_the_chain_with_engine_decisions_and_events(ws):
    _stop(ws)
    track = {
        "track_id": "t-1", "latitude": 40.0, "longitude": 33.0, "altitude": 100.0,
        "confidence": 0.9, "hits": 10, "vx": 5.0, "vy": 0.0, "vz": 0.0,
        "x": 0.0, "y": 0.0, "z": 100.0, "sources": ["camera"],
    }
    decide_full(track, load_roe(DEFAULT_POLICY), chain_path=ws["chain"])
    append_runtime_event(
        RuntimeEvent(event_type="sensor_anomaly", source="imu", source_id="imu-01",
                     timestamp_iso="2026-10-08T12:00:00+00:00", payload={}),
        ws["chain"], load_or_create_keypair(),
    )
    _stop(ws)

    entries = _entries(ws)
    assert [e["chain_index"] for e in entries] == [0, 1, 2, 3]
    assert [e.get("record_type") for e in entries] == ["decision", None, "runtime_event", "decision"]
    assert verify_chain(entries, load_or_create_keypair().public_key()) == (True, None)


def test_record_decision_defaults_to_the_chain_run_graph_writes(isolated_home):
    record_decision("continue", source="planner")
    chain = isolated_home / ".kyvern" / "chain.jsonl"
    assert len(chain.read_text(encoding="utf-8").splitlines()) == 1


@pytest.mark.parametrize("bad", [
    {"inputs": {"blob": "x" * (64 * 1024)}},          # over the 64 KB evidence cap
    {"timestamp_iso": "2026-10-08T12:00:00"},         # no UTC offset
    {"timestamp_iso": "2026-10-08T12:00:00+03:00"},   # not UTC
    {"timestamp_iso": "yesterday"},
    {"source": ""},
])
def test_record_decision_rejects_bad_input_without_recording(ws, bad):
    with pytest.raises(ValidationError):
        _stop(ws, **bad)
    assert not ws["chain"].exists()


def test_record_decision_rejects_an_empty_action(ws):
    with pytest.raises(ValidationError):
        record_decision("", source="safety_controller", chain_path=ws["chain"])
    assert not ws["chain"].exists()


# ── auditor tools ─────────────────────────────────────────────────────────────

def test_kyvern_verify_checks_recorded_decisions_against_the_policy(ws):
    _stop(ws)
    _stop(ws, rule_id="slow-near-people", inputs={"person_distance_m": 1.5})

    res = _cli("cli.kyvern_verify", ws["chain"], "--policy", ws["policy"], "--pubkey", ws["pub"])
    assert res.returncode == 0, res.stdout
    assert ": 2 decisions" in res.stdout
    line = next(x for x in res.stdout.splitlines() if x.startswith("  [0] "))
    assert "action=STOP" in line
    assert "rule_id=stop-on-obstacle" in line
    assert "source=safety_controller" in line


def test_kyvern_verify_fails_a_recorded_decision_without_a_policy(ws):
    _stop(ws, policy_path=None)

    res = _cli("cli.kyvern_verify", ws["chain"], "--policy", ws["policy"], "--pubkey", ws["pub"])
    assert res.returncode == 1
    assert "1 decision(s) not bound to any policy" in res.stdout


def test_kyvern_report_on_recorded_decisions(ws):
    pypdf = pytest.importorskip("pypdf")
    _stop(ws)
    _stop(ws, source="operator", reasoning="operator stopped the robot", rule_id=None)

    res = _cli(
        "cli.kyvern_report", ws["chain"], "--policy", ws["policy"], "--pubkey", ws["pub"],
        "--output", ws["pdf"],
    )
    assert res.returncode == 0, res.stderr
    text = " ".join(" ".join((p.extract_text() or "").split()) for p in pypdf.PdfReader(str(ws["pdf"])).pages)
    assert "No decision records a threat level." in text
    assert "STOP" in text


def test_report_checks_ask_recorded_decisions_for_inputs_and_reasoning(ws):
    from cli.kyvern_report import compute_checks
    from services.decision.audit_chain import PolicyCheck

    _stop(ws)
    _stop(ws, source="operator", inputs={}, reasoning="")
    checks = {
        c.id: c for c in compute_checks(
            _entries(ws), chain_valid=True, broken_idx=None,
            policy_check=PolicyCheck(per_policy={"x": 2}), generated_at=datetime.now(timezone.utc),
        )
    }
    assert checks["risk_fields"].status == "FAIL"
    assert "1 of 2" in checks["risk_fields"].evidence
    assert checks["operation_fields"].status == "PASS"
    assert checks["operator_decisions"].status == "INFO"


def test_mcp_store_reads_recorded_decisions(ws):
    _stop(ws)
    _stop(ws)
    store = AuditChainStore(ws["chain"], public_key_path=ws["pub"])
    store.load()

    assert store.verify_chain_range(None, None).integrity == "OK"
    assert len(store.filter(action="stop")) == 2
