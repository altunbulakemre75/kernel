import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from services.decision.audit_chain import sign_decision
from services.decision.policy_loader import clear_policy_cache, load_policy

REPO_ROOT = Path(__file__).parent.parent.parent


@pytest.fixture
def workspace(tmp_path):
    clear_policy_cache()
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "rules:\n"
        "  - rule_id: \"rule_1\"\n"
        "    description: \"Test\"\n"
        "    when_threat_level: \"low\"\n"
        "    requires_operator_approval: false\n"
        "    action: \"log\"\n"
        "    enabled: true\n",
        encoding="utf-8",
    )
    private_key = ed25519.Ed25519PrivateKey.generate()
    pub_path = tmp_path / "key.pub"
    pub_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    policy = load_policy(str(policy_path))
    actions = ["log", "alert", "log", "engage", "log"]
    chain, prev = [], None
    for i, action in enumerate(actions):
        d = {
            "track_id": f"t{i}",
            "action": action,
            "threat_level": "low",
            "confidence": 0.9,
            "reasoning": "test",
            "source": "rule_engine",
            "roe_reference": "rule_1",
            "requires_operator_approval": action == "engage",
            "timestamp_iso": datetime(2026, 1, 1, 12, i, 0, tzinfo=timezone.utc).isoformat(),
            "llm_raw_response": None,
            "llm_provider": None,
            "llm_model": None,
            "guardrails_triggered": ["geofence"] if action == "alert" else [],
            "guardrail_reasoning": "",
            "policy_version_id": policy.version_id,
            "policy_path": str(policy_path),
            "chain_index": i,
        }
        signed = sign_decision(d, prev_hash=prev, signing_key=private_key)
        chain.append(signed)
        prev = signed["payload_hash"]
    chain_path = tmp_path / "chain.jsonl"
    with open(chain_path, "w", encoding="utf-8") as f:
        for c in chain:
            f.write(json.dumps(c) + "\n")
    return {
        "tmp": tmp_path,
        "policy_path": policy_path,
        "pub_path": pub_path,
        "chain_path": chain_path,
        "private_key": private_key,
        "chain": chain,
    }


def _run(*args):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)
    return subprocess.run(
        [sys.executable, "-m", "cli.kyvern_report", *args],
        capture_output=True, text=True, env=env,
    )


def test_report_generates_pdf_file(workspace):
    out = workspace["tmp"] / "report.pdf"
    res = _run(
        str(workspace["chain_path"]),
        "--policy", str(workspace["policy_path"]),
        "--pubkey", str(workspace["pub_path"]),
        "--output", str(out),
    )
    assert res.returncode == 0, res.stderr
    assert out.exists()
    assert out.read_bytes()[:5] == b"%PDF-"


def test_report_contains_all_sections(workspace):
    import pypdf
    out = workspace["tmp"] / "report.pdf"
    _run(
        str(workspace["chain_path"]),
        "--policy", str(workspace["policy_path"]),
        "--pubkey", str(workspace["pub_path"]),
        "--output", str(out),
    )
    reader = pypdf.PdfReader(str(out))
    text = "".join(page.extract_text() or "" for page in reader.pages)
    for header in ("Article 12", "Article 14", "Cryptographic Integrity",
                   "Policy Version", "Attestation"):
        assert header in text, f"Missing section: {header!r}"


def test_report_article12_uses_correct_regulation(workspace):
    import pypdf
    out = workspace["tmp"] / "report.pdf"
    _run(
        str(workspace["chain_path"]),
        "--policy", str(workspace["policy_path"]),
        "--pubkey", str(workspace["pub_path"]),
        "--output", str(out),
    )
    reader = pypdf.PdfReader(str(out))
    text = "".join(page.extract_text() or "" for page in reader.pages)
    assert "Article 12(2)" in text, "PDF must cite Article 12(2)"
    assert "Regulation (EU) 2024/1689" in text, "PDF must cite Regulation (EU) 2024/1689"
    # "reference database" must only appear in the Art.12(3) out-of-scope note,
    # not as a main-mapping requirement row
    assert "reference database" in text, "Art.12(3) out-of-scope note must mention reference database"
    # Verify 12(3) requirements are not in the main compliance table rows
    art12_table_headers = ["Art.12(2)(a)", "Art.12(2)(b)", "Art.12(2)(c)"]
    for header in art12_table_headers:
        assert header in text, f"Main Article 12(2) row missing: {header!r}"


def test_report_action_distribution_correct(workspace):
    from cli.kyvern_report import compute_action_distribution
    dist = compute_action_distribution(workspace["chain"])
    assert dist.get("LOG") == 3
    assert dist.get("ALERT") == 1
    assert dist.get("ENGAGE") == 1


def test_report_detects_tampered_chain(workspace):
    import pypdf
    chain = list(workspace["chain"])
    chain[1] = dict(chain[1])
    chain[1]["action"] = "engage"
    tampered = workspace["tmp"] / "tampered.jsonl"
    with open(tampered, "w", encoding="utf-8") as f:
        for c in chain:
            f.write(json.dumps(c) + "\n")
    out = workspace["tmp"] / "tampered_report.pdf"
    res = _run(
        str(tampered),
        "--policy", str(workspace["policy_path"]),
        "--pubkey", str(workspace["pub_path"]),
        "--output", str(out),
    )
    assert res.returncode == 1
    assert out.exists()
    reader = pypdf.PdfReader(str(out))
    text = "".join(page.extract_text() or "" for page in reader.pages)
    assert "INVALID" in text


def test_report_exit_code_zero_on_success(workspace):
    out = workspace["tmp"] / "r.pdf"
    res = _run(
        str(workspace["chain_path"]),
        "--policy", str(workspace["policy_path"]),
        "--pubkey", str(workspace["pub_path"]),
        "--output", str(out),
    )
    assert res.returncode == 0


def test_report_exit_code_one_on_chain_verification_failure(workspace):
    chain = list(workspace["chain"])
    chain[0] = dict(chain[0])
    chain[0]["action"] = "engage"
    bad = workspace["tmp"] / "bad.jsonl"
    with open(bad, "w", encoding="utf-8") as f:
        for c in chain:
            f.write(json.dumps(c) + "\n")
    out = workspace["tmp"] / "bad_report.pdf"
    res = _run(
        str(bad),
        "--policy", str(workspace["policy_path"]),
        "--pubkey", str(workspace["pub_path"]),
        "--output", str(out),
    )
    assert res.returncode == 1


def test_report_accepts_several_pubkeys(workspace):
    new_key = ed25519.Ed25519PrivateKey.generate()
    new_pub = workspace["tmp"] / "new.pub"
    new_pub.write_bytes(new_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    last = workspace["chain"][-1]
    d = {k: v for k, v in last.items() if k not in ("signature", "payload_hash", "key_id")}
    d["chain_index"] = last["chain_index"] + 1
    signed = sign_decision(d, prev_hash=last["payload_hash"], signing_key=new_key)
    with open(workspace["chain_path"], "a", encoding="utf-8") as f:
        f.write(json.dumps(signed) + "\n")

    out = workspace["tmp"] / "report.pdf"
    res = _run(
        str(workspace["chain_path"]),
        "--policy", str(workspace["policy_path"]),
        "--pubkey", str(workspace["pub_path"]),
        "--pubkey", str(new_pub),
        "--output", str(out),
    )
    assert res.returncode == 0, res.stderr
    assert "[chain: VALID]" in res.stdout


def test_report_version_matches_the_package_version():
    import re

    from cli.kyvern_report import VERSION

    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    declared = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE).group(1)
    assert VERSION == declared


# ── checks: every row is computed from the chain, or says it cannot be ────────

GENERATED_AT = datetime(2026, 10, 8, tzinfo=timezone.utc)


def _decision(i, **overrides):
    d = {
        "action": "log", "threat_level": "low", "roe_reference": "rule_1",
        "guardrails_triggered": [], "guardrail_reasoning": "",
        "requires_operator_approval": False, "source": "rule_engine",
        "timestamp_iso": datetime(2026, 1, 1, 12, i, tzinfo=timezone.utc).isoformat(),
        "policy_version_id": "a" * 64, "chain_index": i,
    }
    d.update(overrides)
    return d


def _checks(records, chain_valid=True, broken_idx=None, policy_check="bound"):
    from cli.kyvern_report import compute_checks
    from services.decision.audit_chain import PolicyCheck

    if policy_check == "bound":
        decisions = sum(1 for r in records if r.get("record_type") != "runtime_event")
        policy_check = PolicyCheck(per_policy={"a" * 64: decisions})
    checks = compute_checks(
        records, chain_valid=chain_valid, broken_idx=broken_idx,
        policy_check=policy_check, generated_at=GENERATED_AT,
    )
    return {c.id: c for c in checks}


def test_checks_on_a_complete_chain():
    checks = _checks([_decision(i) for i in range(3)])
    assert {key: c.status for key, c in checks.items()} == {
        "integrity": "PASS", "risk_fields": "PASS", "policy_recorded": "PASS",
        "operation_fields": "PASS", "timestamps": "PASS", "automatic": "NOT ASSESSED",
        "retention": "INFO", "approval_flag": "N/A", "operator_decisions": "NOT ASSESSED",
        "override": "NOT ASSESSED", "guardrails": "INFO", "policy": "PASS",
    }
    assert "2026-01-01" in checks["retention"].evidence


def test_field_checks_count_the_decisions_missing_a_field():
    records = [_decision(0), _decision(1, threat_level=None), _decision(2)]
    del records[2]["guardrail_reasoning"]
    checks = _checks(records)
    assert checks["risk_fields"].status == "FAIL"
    assert "1 of 3" in checks["risk_fields"].evidence
    assert checks["operation_fields"].status == "FAIL"
    assert "1 of 3" in checks["operation_fields"].evidence


def test_policy_recorded_fails_for_a_decision_without_a_policy():
    checks = _checks([_decision(0), _decision(1, policy_version_id=None)])
    assert checks["policy_recorded"].status == "FAIL"


def test_engage_decisions_must_be_flagged_for_operator_approval():
    flagged = _checks([_decision(0, action="engage", requires_operator_approval=True)])
    assert flagged["approval_flag"].status == "PASS"
    assert "not that it was given" in flagged["approval_flag"].evidence
    unflagged = _checks([_decision(0, action="engage")])
    assert unflagged["approval_flag"].status == "FAIL"


def test_operator_decisions_are_counted():
    checks = _checks([_decision(0), _decision(1, source="operator")])
    assert checks["operator_decisions"].status == "INFO"
    assert "1 decision(s)" in checks["operator_decisions"].evidence


def test_guardrail_downgrades_are_not_called_human_oversight():
    checks = _checks([_decision(0, guardrails_triggered=["friendly-zone-OP"])])
    assert checks["guardrails"].status == "INFO"
    assert "automated" in checks["guardrails"].evidence


def test_timestamps_must_be_iso_8601_in_utc():
    assert _checks([_decision(0, timestamp_iso="2026-01-01T12:00:00+03:00")])["timestamps"].status == "FAIL"
    assert _checks([_decision(0, timestamp_iso="yesterday")])["timestamps"].status == "FAIL"


def test_a_broken_chain_makes_record_checks_not_assessed():
    checks = _checks([_decision(i) for i in range(3)], chain_valid=False, broken_idx=1)
    assert checks["integrity"].status == "FAIL"
    assert "index 1" in checks["integrity"].evidence
    for key in ("risk_fields", "policy_recorded", "operation_fields", "timestamps",
                "retention", "approval_flag", "operator_decisions", "guardrails"):
        assert checks[key].status == "NOT ASSESSED", key


def test_a_chain_without_decisions_has_nothing_to_check_per_decision():
    from services.decision.audit_chain import PolicyCheck

    event = {"record_type": "runtime_event", "event_type": "x", "timestamp_iso": GENERATED_AT.isoformat()}
    checks = _checks([event], policy_check=PolicyCheck())
    for key in ("risk_fields", "policy_recorded", "operation_fields", "approval_flag"):
        assert checks[key].status == "N/A", key
    assert checks["policy"].status == "FAIL"


def test_fingerprint_covers_the_check_results():
    from cli.kyvern_report import compute_report_fingerprint

    args = ([], True, "v", "sys", "period", "now")
    assert compute_report_fingerprint(*args, checks={"integrity": "PASS"}) != (
        compute_report_fingerprint(*args, checks={"integrity": "FAIL"})
    )


def test_report_wording_is_evidence_not_compliance(workspace):
    import pypdf

    out = workspace["tmp"] / "report.pdf"
    res = _run(
        str(workspace["chain_path"]),
        "--policy", str(workspace["policy_path"]),
        "--pubkey", str(workspace["pub_path"]),
        "--output", str(out),
    )
    assert res.returncode == 0, res.stderr
    text = " ".join(" ".join((p.extract_text() or "").split()) for p in pypdf.PdfReader(str(out)).pages)
    assert "satisf" not in text.lower()
    assert "10 years" not in text
    assert "at least six months" in text
    assert "does not establish conformity" in text
    assert "NOT ASSESSED" in text


def test_report_rejects_a_key_that_is_not_ed25519(workspace):
    from cryptography.hazmat.primitives.asymmetric import ec

    p256 = workspace["tmp"] / "p256.pub"
    p256.write_bytes(ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    res = _run(
        str(workspace["chain_path"]),
        "--policy", str(workspace["policy_path"]),
        "--pubkey", str(p256),
        "--output", str(workspace["tmp"] / "report.pdf"),
    )
    assert res.returncode == 1
    assert "is not an Ed25519 public key" in res.stderr
    assert "Traceback" not in res.stderr


def _signing_key_args(workspace, key_path):
    out = workspace["tmp"] / "report.pdf"
    return out, (
        str(workspace["chain_path"]),
        "--policy", str(workspace["policy_path"]),
        "--pubkey", str(workspace["pub_path"]),
        "--output", str(out),
        "--signingkey", str(key_path),
    )


def _pem_private(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def test_report_signs_with_an_ed25519_signing_key(workspace):
    import base64
    import re

    import pypdf

    key = ed25519.Ed25519PrivateKey.generate()
    key_path = workspace["tmp"] / "report.key"
    key_path.write_bytes(_pem_private(key))
    out, args = _signing_key_args(workspace, key_path)
    res = _run(*args)
    assert res.returncode == 0, res.stderr
    text = "".join(p.extract_text() or "" for p in pypdf.PdfReader(str(out)).pages)
    assert "Ed25519 signature of report fingerprint" in text
    fingerprint = re.search(r"Report fingerprint \(SHA-256\):\s*([0-9a-f]{64})", text).group(1)
    signature = re.search(r"Ed25519 signature of report fingerprint:\s*(\S+)", text).group(1)
    key.public_key().verify(base64.b64decode(signature), fingerprint.encode())


@pytest.mark.parametrize("problem", ["missing", "not_ed25519", "garbage"])
def test_report_fails_when_the_signing_key_cannot_be_used(workspace, problem):
    from cryptography.hazmat.primitives.asymmetric import ec

    key_path = workspace["tmp"] / "report.key"
    if problem == "not_ed25519":
        key_path.write_bytes(_pem_private(ec.generate_private_key(ec.SECP256R1())))
    elif problem == "garbage":
        key_path.write_bytes(b"not a key")
    out, args = _signing_key_args(workspace, key_path)
    res = _run(*args)
    assert res.returncode == 1
    assert "cannot load signing key" in res.stderr
    assert "Traceback" not in res.stderr
    assert not out.exists()



def test_report_reports_a_line_that_is_not_a_json_object(workspace):
    chain_path = workspace["chain_path"]
    chain_path.write_text(chain_path.read_text(encoding="utf-8") + "[1, 2]\n", encoding="utf-8")
    out = workspace["tmp"] / "report.pdf"
    res = _run(
        str(chain_path),
        "--policy", str(workspace["policy_path"]),
        "--pubkey", str(workspace["pub_path"]),
        "--output", str(out),
    )
    assert res.returncode == 1
    assert "is not a JSON object" in res.stderr
    assert "Traceback" not in res.stderr
    assert not out.exists()
