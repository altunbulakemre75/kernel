
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from services.decision.audit_chain import (
    sign_decision,
    verify_decision_against_policy,
)
from services.decision.policy_loader import (
    clear_policy_cache,
    load_policy,
    policy_hash,
)


@pytest.fixture
def temp_policy_file(tmp_path):
    clear_policy_cache()
    p = tmp_path / "test_policy.yaml"
    content = """
rules:
  - rule_id: "rule_1"
    description: "Test"
    when_threat_level: "low"
    requires_operator_approval: false
    action: "log"
    enabled: true
"""
    p.write_text(content, encoding="utf-8")
    return p


def test_policy_hash_is_stable(temp_policy_file):
    policy1 = load_policy(str(temp_policy_file))
    clear_policy_cache()
    
    for _ in range(100):
        policy2 = load_policy(str(temp_policy_file))
        assert policy1.version_id == policy2.version_id
        clear_policy_cache()


def test_policy_hash_changes_on_edit(temp_policy_file):
    policy1 = load_policy(str(temp_policy_file))
    clear_policy_cache()
    
    text = temp_policy_file.read_text(encoding="utf-8")
    text = text.replace("low", "medium")
    temp_policy_file.write_text(text, encoding="utf-8")
    
    policy2 = load_policy(str(temp_policy_file))
    assert policy1.version_id != policy2.version_id


def test_yaml_key_order_doesnt_affect_hash():
    d1 = {"rules": [{"a": 1, "b": 2}]}
    d2 = {"rules": [{"b": 2, "a": 1}]}
    
    assert policy_hash(d1) == policy_hash(d2)


def test_load_policy_returns_cached_instance(temp_policy_file):
    policy1 = load_policy(str(temp_policy_file))
    policy2 = load_policy(str(temp_policy_file))
    assert policy1 is policy2


def test_clear_cache_forces_reload(temp_policy_file):
    policy1 = load_policy(str(temp_policy_file))
    clear_policy_cache()
    policy2 = load_policy(str(temp_policy_file))
    assert policy1 is not policy2
    assert policy1.version_id == policy2.version_id


@pytest.mark.asyncio
async def test_decision_carries_policy_version(temp_policy_file):
    from services.decision.llm_graph import run_graph
    
    track = {
        "track_id": "test_1",
        "latitude": 40.0, "longitude": 33.0,
        "altitude": 100.0, "confidence": 0.9, "hits": 10,
        "vx": 5.0, "vy": 0.0, "vz": 0.0,
        "x": 0.0, "y": 0.0, "z": 100.0,
        "sources": ["camera"],
    }
    
    rules = []  # Empty for test since we just want to see it run through graph
    
    decision = await run_graph(
        track, 
        roe_rules=rules, 
        policy_path=str(temp_policy_file)
    )
    
    policy = load_policy(str(temp_policy_file))
    assert decision.policy_version_id == policy.version_id
    assert decision.policy_path == str(temp_policy_file)


def test_verify_decision_against_policy_match(temp_policy_file):
    policy = load_policy(str(temp_policy_file))
    
    decision = {
        "track_id": "test",
        "policy_version_id": policy.version_id,
        "policy_path": str(temp_policy_file)
    }
    
    private_key = ed25519.Ed25519PrivateKey.generate()
    signed = sign_decision(decision, prev_hash=None, signing_key=private_key)
    
    is_valid, reason = verify_decision_against_policy(signed, str(temp_policy_file), private_key.public_key())
    assert is_valid is True
    assert reason == "Match"


def test_verify_decision_against_wrong_policy_fails(temp_policy_file):
    load_policy(str(temp_policy_file))

    decision = {
        "track_id": "test",
        "policy_version_id": "wrong_hash",
        "policy_path": str(temp_policy_file)
    }
    
    private_key = ed25519.Ed25519PrivateKey.generate()
    signed = sign_decision(decision, prev_hash=None, signing_key=private_key)
    
    is_valid, reason = verify_decision_against_policy(signed, str(temp_policy_file), private_key.public_key())
    assert is_valid is False
    assert "Policy version mismatch" in reason
