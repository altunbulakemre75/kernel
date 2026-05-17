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
        [sys.executable, "-m", "cli.kernel_report", *args],
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


def test_report_action_distribution_correct(workspace):
    from cli.kernel_report import compute_action_distribution
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
