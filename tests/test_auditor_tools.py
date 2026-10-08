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

from kyvern import record_decision
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


def _report(ws, *policies, extra=()):
    policy_args = [a for p in policies for a in ("--policy", p)]
    return _cli(
        "cli.kyvern_report", ws["chain"], *policy_args,
        "--pubkey", ws["pub"], "--output", ws["pdf"], *extra,
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
    assert "Single policy version in effect" not in text
    assert "No decision in the period records a policy version." in text


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


def test_verify_json_names_one_policy_version_only_for_one_policy(ws):
    _decide(ws, 1, policy=ws["policy"])
    _decide(ws, 1, policy=ws["updated"], prefix="u")
    ids = [load_policy(str(p)).version_id for p in (ws["policy"], ws["updated"])]

    out = json.loads(_verify(ws, ws["policy"], ws["updated"], extra=["--json"]).stdout)
    assert out["policy_version_ids"] == ids
    assert out["policy_version_id"] is None

    out = json.loads(_verify(ws, ws["policy"], extra=["--json"]).stdout)
    assert out["policy_version_id"] == ids[0]


def test_the_same_policy_given_twice_is_listed_once(ws):
    _decide(ws, 2, policy=ws["policy"])

    res = _verify(ws, ws["policy"], ws["policy"])
    assert res.returncode == 0, res.stdout
    assert res.stdout.count("Policy match:") == 1
    assert ": 2 decisions" in res.stdout
    assert "Audit hash:" in res.stdout
    out = json.loads(_verify(ws, ws["policy"], ws["policy"], extra=["--json"]).stdout)
    assert out["policy_version_ids"] == [out["policy_version_id"]]


def test_verify_json_for_an_empty_chain_has_the_usual_keys(ws):
    _decide(ws, 1, policy=ws["policy"])
    usual = json.loads(_verify(ws, ws["policy"], extra=["--json"]).stdout)
    ws["chain"].write_text("", encoding="utf-8")

    res = _verify(ws, ws["policy"], extra=["--json"])
    assert res.returncode == 1
    out = json.loads(res.stdout)
    assert out.keys() == usual.keys()
    assert out["errors"] == ["No decisions found in chain file"]
    assert out["decision_count"] == 0


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


@pytest.mark.parametrize("policy_id", [5, ["not", "text"]])
def test_tools_survive_a_policy_id_that_is_not_text(ws, policy_id):
    _decide(ws, 2, policy=ws["policy"])
    _tamper(ws, 1, policy_version_id=policy_id)

    res = _verify(ws, ws["policy"])
    assert res.returncode == 1
    assert "Traceback" not in res.stderr, res.stderr
    assert "1 decision(s) bound to a policy not given with --policy" in res.stdout

    res = _report(ws, ws["policy"])
    assert res.returncode == 1
    assert "Traceback" not in res.stderr, res.stderr
    assert "[chain: INVALID] [policy: FAILED]" in res.stdout


def test_report_prints_markup_like_text_as_text(ws):
    _decide(ws, 1, policy=ws["policy"])
    _tamper(ws, 0, policy_version_id="<b>evil</b>", timestamp_iso="<i>2026-10-08T00:00:00+00:00")

    res = _report(ws, ws["policy"], extra=["--system-id", "R&D <lab>", "--operator", "<font>ops"])
    assert res.returncode == 1
    assert "Traceback" not in res.stderr, res.stderr
    text = _pdf_text(ws["pdf"])
    assert "System ID: R&D <lab>" in text
    assert "Operator: <font>ops" in text
    assert "Period: <i>2026-10/<i>2026-10" in text
    assert "(<b>evil</b>)" in text


# ── tampered chains ───────────────────────────────────────────────────────────
# An auditor runs these tools on chains they do not trust. A tampered record can
# hold any JSON value in any field; the tools must report the chain as failed,
# never crash and never call it OK.

def test_mcp_range_with_no_entries_is_not_ok(ws):
    _decide(ws, 2, policy=ws["policy"])
    store = AuditChainStore(ws["chain"], public_key_path=ws["pub"])
    store.load()

    result = store.verify_chain_range(10, 20)
    assert result.integrity == "UNKNOWN"
    assert result.total_count == 0
    # A negative end must not count from the end of the chain.
    assert store.verify_chain_range(0, -2).integrity == "UNKNOWN"


def test_mcp_range_keeps_an_entry_whose_chain_index_was_removed(ws):
    _decide(ws, 3, policy=ws["policy"])
    lines = ws["chain"].read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[1])
    del record["chain_index"]
    lines[1] = json.dumps(record)
    ws["chain"].write_text("\n".join(lines) + "\n", encoding="utf-8")
    store = AuditChainStore(ws["chain"], public_key_path=ws["pub"])
    store.load()

    result = store.verify_chain_range(0, 1)
    assert result.integrity == "BROKEN"
    assert result.first_break["id"] == 1


_TAMPER_VALUES = (5, [5], {"k": [5]})

# Runs each CLI's main() for every case in one process, so the sweep stays fast;
# prints {case: exit code, or the traceback if main() raised}.
_DRIVER = """
import importlib, io, json, sys, traceback
cases = json.loads(open(sys.argv[1], encoding="utf-8").read())
results = {}
for name, (module, argv) in cases.items():
    sys.argv = [module, *argv]
    sys.stdout = sys.stderr = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    try:
        importlib.import_module(module).main()
        results[name] = "returned"
    except SystemExit as exc:
        results[name] = exc.code
    except Exception:
        results[name] = traceback.format_exc()
sys.stdout = sys.__stdout__
print(json.dumps(results))
"""


def test_auditor_tools_survive_any_tampered_field(ws, tmp_path):
    _decide(ws, 1, policy=ws["policy"])
    _event(ws)
    record_decision(
        "stop", source="safety_controller", reasoning="obstacle at 0.4 m",
        inputs={"obstacle_distance_m": 0.4}, rule_id="stop-on-obstacle", chain_path=ws["chain"],
    )
    records = [json.loads(line) for line in ws["chain"].read_text(encoding="utf-8").splitlines()]

    cases, failures = {}, {}
    for index, record in enumerate(records):
        for field_name in record:
            for n, value in enumerate(_TAMPER_VALUES):
                name = f"[{index}].{field_name}={value!r}"
                tampered = [dict(r) for r in records]
                tampered[index][field_name] = value
                chain = tmp_path / f"{index}-{field_name}-{n}.jsonl"
                chain.write_text("".join(json.dumps(r) + "\n" for r in tampered), encoding="utf-8")

                common = [str(chain), "--policy", str(ws["policy"]), "--pubkey", str(ws["pub"])]
                cases[f"kyvern-verify {name}"] = ["cli.kyvern_verify", common]
                cases[f"kyvern-verify --json {name}"] = ["cli.kyvern_verify", [*common, "--json"]]
                cases[f"kyvern-report {name}"] = [
                    "cli.kyvern_report", [*common, "--output", str(tmp_path / "report.pdf")],
                ]
                try:
                    store = AuditChainStore(chain, public_key_path=ws["pub"])
                    store.load()
                    integrity = store.verify_chain_range(None, None).integrity
                except Exception as exc:
                    integrity = repr(exc)
                if integrity != "BROKEN":
                    failures[f"store.verify_chain_range {name}"] = integrity

    spec = tmp_path / "cases.json"
    spec.write_text(json.dumps(cases), encoding="utf-8")
    res = subprocess.run(
        [sys.executable, "-c", _DRIVER, str(spec)], capture_output=True, text=True,
        env=dict(os.environ, PYTHONPATH=str(REPO_ROOT)),
    )
    assert res.returncode == 0, res.stderr
    failures.update({name: code for name, code in json.loads(res.stdout).items() if code != 1})
    assert not failures, "\n".join(f"{name}: {outcome}" for name, outcome in failures.items())
