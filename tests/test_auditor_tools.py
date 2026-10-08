"""End to end: what the pipeline writes, the auditor tools read correctly.

Runs real decide_full() output (and a RuntimeEvent) through kyvern-verify,
kyvern-report and the MCP store's range check. Each tool used to disagree with
the pipeline on one of these chains; see
docs/superpowers/specs/2026-10-08-auditor-tools-design.md.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from kyvern.audit import AuditChainStore
from services.decision.audit_chain import append_runtime_event, load_or_create_keypair
from services.decision.policy_loader import clear_policy_cache, load_policy
from services.decision.roe import load_roe
from services.decision.threat_graph import decide_full
from shared.schemas import RuntimeEvent

REPO_ROOT = Path(__file__).parent.parent
DEFAULT_POLICY = REPO_ROOT / "config" / "policies" / "default.yaml"

TRACK = {
    "latitude": 40.0, "longitude": 33.0, "altitude": 100.0,
    "confidence": 0.9, "hits": 10,
    "vx": 5.0, "vy": 0.0, "vz": 0.0, "x": 0.0, "y": 0.0, "z": 100.0,
    "sources": ["camera"],
}


@pytest.fixture
def ws(tmp_path, isolated_home):
    """Chain path, the signing public key the pipeline will create, and two policies."""
    clear_policy_cache()
    updated = tmp_path / "updated.yaml"
    updated.write_text(
        DEFAULT_POLICY.read_text(encoding="utf-8").replace("POL-1", "POL-1-REV2"),
        encoding="utf-8",
    )
    return {
        "chain": tmp_path / "chain.jsonl",
        "pub": isolated_home / ".kyvern" / "keys" / "signing.pub",
        "policy": DEFAULT_POLICY,
        "updated": updated,
        "pdf": tmp_path / "report.pdf",
    }


def _decide(ws, n, policy=None, prefix="t"):
    rules = load_roe(policy or DEFAULT_POLICY)
    for i in range(n):
        decide_full(
            dict(TRACK, track_id=f"{prefix}-{i}"), rules,
            policy_path=str(policy) if policy else None, chain_path=ws["chain"],
        )


def _event(ws):
    event = RuntimeEvent(
        event_type="sensor_anomaly", source="imu_monitor", source_id="imu-01",
        timestamp_iso="2026-10-08T12:00:00+00:00", payload={"drift_deg": 4.5},
    )
    append_runtime_event(event, ws["chain"], load_or_create_keypair())


def _tamper(ws, index, **fields):
    """Rewrite chain entry `index` without re-signing it."""
    lines = ws["chain"].read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[index])
    record.update(fields)
    lines[index] = json.dumps(record)
    ws["chain"].write_text("\n".join(lines) + "\n", encoding="utf-8")


def _cli(module, *args):
    env = dict(os.environ, PYTHONPATH=str(REPO_ROOT))
    return subprocess.run(
        [sys.executable, "-m", module, *map(str, args)], capture_output=True, text=True, env=env,
    )


def _verify(ws, *policies, extra=()):
    policy_args = [a for p in policies for a in ("--policy", p)]
    return _cli("cli.kyvern_verify", ws["chain"], *policy_args, "--pubkey", ws["pub"], *extra)


def _report(ws, *policies):
    policy_args = [a for p in policies for a in ("--policy", p)]
    return _cli(
        "cli.kyvern_report", ws["chain"], *policy_args,
        "--pubkey", ws["pub"], "--output", ws["pdf"],
    )


def _pdf_text(path):
    pypdf = pytest.importorskip("pypdf")
    reader = pypdf.PdfReader(str(path))
    return " ".join(" ".join((page.extract_text() or "").split()) for page in reader.pages)


def test_bound_decisions_and_runtime_event(ws):
    _decide(ws, 2, policy=ws["policy"])
    _event(ws)
    _decide(ws, 1, policy=ws["policy"], prefix="u")

    res = _verify(ws, ws["policy"])
    assert res.returncode == 0, res.stdout
    assert "Chain integrity: VALID (3 decisions, 1 runtime events, all signed)" in res.stdout
    assert ": 3 decisions" in res.stdout
    event_line = next(line for line in res.stdout.splitlines() if line.startswith("  [2] "))
    assert event_line.endswith("event=sensor_anomaly source=imu_monitor")
    assert "UNKNOWN" not in res.stdout

    out = json.loads(_verify(ws, ws["policy"], extra=["--json"]).stdout)
    assert out["decision_count"] == 3
    assert out["runtime_event_count"] == 1
    assert out["unbound_decisions"] == []

    res = _report(ws, ws["policy"])
    assert res.returncode == 0, res.stderr
    assert "[chain: VALID] [policy: OK]" in res.stdout
    text = _pdf_text(ws["pdf"])
    assert "Total decisions in chain: 3" in text
    assert "Runtime events in chain: 1" in text
    assert "sensor_anomaly" in text
    assert "UNKNOWN" not in text
    assert "Verifiable policy deployment failed" not in text

    store = AuditChainStore(ws["chain"], public_key_path=ws["pub"])
    store.load()
    for start, end in ((None, None), (1, None), (2, 3), (3, 3)):
        assert store.verify_chain_range(start, end).integrity == "OK", (start, end)


def test_decisions_recorded_without_a_policy(ws):
    _decide(ws, 2)

    res = _verify(ws, ws["policy"])
    assert res.returncode == 1
    assert "Chain integrity: VALID (2 decisions, all signed)" in res.stdout
    assert (
        "2 decision(s) not bound to any policy (recorded without policy_path) at [0, 1]"
        in res.stdout
    )

    res = _report(ws, ws["policy"])
    assert res.returncode == 1
    assert "Traceback" not in res.stderr
    assert "[chain: VALID] [policy: FAILED]" in res.stdout
    text = _pdf_text(ws["pdf"])
    assert "(none recorded)" in text
    assert "Verifiable policy deployment failed: 2 decision(s) not bound" in text


def test_chain_spanning_a_policy_update(ws):
    _decide(ws, 1, policy=ws["policy"])
    _decide(ws, 2, policy=ws["updated"], prefix="u")
    updated_short = load_policy(str(ws["updated"])).version_short

    res = _verify(ws, ws["policy"], ws["updated"])
    assert res.returncode == 0, res.stdout
    assert ": 1 decisions" in res.stdout
    assert ": 2 decisions" in res.stdout

    res = _verify(ws, ws["policy"])
    assert res.returncode == 1
    assert f"2 decision(s) bound to a policy not given with --policy ({updated_short}) at [1, 2]" in (
        res.stdout
    )

    res = _report(ws, ws["policy"], ws["updated"])
    assert res.returncode == 0, res.stderr


def test_report_checks_the_chain_against_the_policy(ws):
    _decide(ws, 2, policy=ws["policy"])

    res = _report(ws, ws["updated"])
    assert res.returncode == 1
    assert "[chain: VALID] [policy: FAILED]" in res.stdout
    assert "bound to a policy not given with --policy" in res.stderr
    text = _pdf_text(ws["pdf"])
    assert "Verifiable policy deployment failed" in text


def test_chain_without_decisions_fails_the_policy_check(ws):
    # Only RuntimeEvents (or a chain cut down to them): no Decision is bound to the policy.
    _event(ws)

    res = _verify(ws, ws["policy"])
    assert res.returncode == 1, res.stdout
    assert "Chain integrity: VALID (0 decisions, 1 runtime events, all signed)" in res.stdout
    assert "Policy match: FAILED" in res.stdout
    assert "no decisions in the chain to check against a policy" in res.stdout
    assert json.loads(_verify(ws, ws["policy"], extra=["--json"]).stdout)["policy_match"] is False

    res = _report(ws, ws["policy"])
    assert res.returncode == 1
    assert "[chain: VALID] [policy: FAILED]" in res.stdout
    text = _pdf_text(ws["pdf"])
    assert "Verifiable policy deployment failed: no decisions in the chain" in text


def test_broken_chain_does_not_pass_the_policy_check(ws):
    # Every Decision still names the right policy, but the records are no longer authentic.
    _decide(ws, 2, policy=ws["policy"])
    _tamper(ws, 1, threat_level="LOW")

    res = _verify(ws, ws["policy"])
    assert res.returncode == 1
    assert "Chain integrity: INVALID" in res.stdout
    assert "Policy match: FAILED" in res.stdout
    assert "chain integrity is broken at index 1" in res.stdout
    out = json.loads(_verify(ws, ws["policy"], extra=["--json"]).stdout)
    assert out["chain_valid"] is False
    assert out["policy_match"] is False

    res = _report(ws, ws["policy"])
    assert res.returncode == 1
    assert "[chain: INVALID] [policy: FAILED]" in res.stdout
    text = _pdf_text(ws["pdf"])
    assert "Verifiable policy deployment failed: chain integrity is broken at index 1" in text
