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


@pytest.fixture
def temp_workspace(tmp_path):
    clear_policy_cache()
    
    policy_path = tmp_path / "policy.yaml"
    policy_content = """
rules:
  - rule_id: "rule_1"
    description: "Test"
    when_threat_level: "low"
    requires_operator_approval: false
    action: "log"
    enabled: true
"""
    policy_path.write_text(policy_content, encoding="utf-8")
    
    private_key = ed25519.Ed25519PrivateKey.generate()
    pub_path = tmp_path / "key.pub"
    
    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pub_path.write_bytes(pub_bytes)
    
    policy = load_policy(str(policy_path))
    
    # Generate chain
    chain = []
    prev_hash = None
    for i in range(3):
        d = {
            "track_id": f"track_{i}",
            "action": "log",
            "threat_level": "low",
            "confidence": 0.9,
            "reasoning": "testing",
            "source": "rule_engine",
            "roe_reference": "rule_1",
            "requires_operator_approval": False,
            "timestamp_iso": datetime.now(timezone.utc).isoformat(),
            "llm_raw_response": None,
            "llm_provider": None,
            "llm_model": None,
            "guardrails_triggered": [],
            "guardrail_reasoning": "",
            "policy_version_id": policy.version_id,
            "policy_path": str(policy_path),
            "chain_index": i
        }
        signed = sign_decision(d, prev_hash=prev_hash, signing_key=private_key)
        chain.append(signed)
        prev_hash = signed["payload_hash"]
        
    chain_path = tmp_path / "chain.jsonl"
    with open(chain_path, "w", encoding="utf-8") as f:
        for c in chain:
            f.write(json.dumps(c) + "\n")
            
    return {
        "policy_path": policy_path,
        "pub_path": pub_path,
        "chain_path": chain_path,
        "private_key": private_key,
        "chain": chain
    }


def run_cli(*args):
    cmd = [sys.executable, "-m", "cli.kernel_verify"] + list(args)
    # Put the project root in PYTHONPATH to ensure cli.kernel_verify is reachable
    env = os.environ.copy()
    if "PYTHONPATH" in env:
        env["PYTHONPATH"] = f"{Path(__file__).parent.parent.parent}:{env['PYTHONPATH']}"
    else:
        env["PYTHONPATH"] = str(Path(__file__).parent.parent.parent)
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    return result


def test_verify_valid_chain_returns_zero(temp_workspace):
    res = run_cli(
        str(temp_workspace["chain_path"]),
        "--policy", str(temp_workspace["policy_path"]),
        "--pubkey", str(temp_workspace["pub_path"])
    )
    assert res.returncode == 0
    assert "Chain integrity: VALID" in res.stdout
    assert "Policy match: " in res.stdout
    assert "Signature verification: PASSED" in res.stdout


def test_verify_tampered_chain_returns_one(temp_workspace):
    chain = temp_workspace["chain"]
    chain[1]["action"] = "alert"
    
    chain_path = temp_workspace["chain_path"]
    with open(chain_path, "w", encoding="utf-8") as f:
        for c in chain:
            f.write(json.dumps(c) + "\n")
            
    res = run_cli(
        str(chain_path),
        "--policy", str(temp_workspace["policy_path"]),
        "--pubkey", str(temp_workspace["pub_path"])
    )
    assert res.returncode == 1
    assert "Chain integrity: INVALID" in res.stdout


def test_verify_wrong_policy_returns_one(temp_workspace):
    wrong_policy_path = temp_workspace["policy_path"].parent / "wrong.yaml"
    wrong_policy_path.write_text("rules: []", encoding="utf-8")
    
    res = run_cli(
        str(temp_workspace["chain_path"]),
        "--policy", str(wrong_policy_path),
        "--pubkey", str(temp_workspace["pub_path"])
    )
    assert res.returncode == 1
    assert "Decision [0] mismatch" in res.stdout


def test_verify_missing_signature_returns_one(temp_workspace):
    chain = temp_workspace["chain"]
    del chain[1]["signature"]
    
    chain_path = temp_workspace["chain_path"]
    with open(chain_path, "w", encoding="utf-8") as f:
        for c in chain:
            f.write(json.dumps(c) + "\n")
            
    res = run_cli(
        str(chain_path),
        "--policy", str(temp_workspace["policy_path"]),
        "--pubkey", str(temp_workspace["pub_path"])
    )
    assert res.returncode == 1
    assert "Chain integrity: INVALID" in res.stdout


def test_json_output_format_parses_correctly(temp_workspace):
    res = run_cli(
        str(temp_workspace["chain_path"]),
        "--policy", str(temp_workspace["policy_path"]),
        "--pubkey", str(temp_workspace["pub_path"]),
        "--json"
    )
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["chain_valid"] is True
    assert data["policy_match"] is True
    assert data["signature_valid"] is True
    assert len(data["decisions"]) == 3
    assert data["policy_version_id"] is not None
    assert data["errors"] == []


def test_verbose_flag_shows_full_payloads(temp_workspace):
    res = run_cli(
        str(temp_workspace["chain_path"]),
        "--policy", str(temp_workspace["policy_path"]),
        "--pubkey", str(temp_workspace["pub_path"]),
        "--verbose"
    )
    assert res.returncode == 0
    # "track_0" is in the full payload dump
    assert "track_0" in res.stdout
