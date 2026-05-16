import copy

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from services.decision.audit_chain import (
    canonical_json,
    sign_decision,
    verify_chain,
    verify_decision,
)


@pytest.fixture
def sample_decision():
    return {
        "track_id": "test_track_1",
        "action": "log",
        "threat_level": "low",
        "confidence": 0.95,
        "reasoning": "Test reasoning",
        "source": "rule_engine",
        "roe_reference": "rule_1",
        "requires_operator_approval": False,
        "timestamp_iso": "2026-05-16T12:00:00Z",
        "llm_raw_response": None,
        "llm_provider": None,
        "llm_model": None,
        "guardrails_triggered": [],
        "guardrail_reasoning": "",
    }


def test_sign_and_verify_roundtrip(sample_decision):
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    signed = sign_decision(sample_decision, prev_hash=None, signing_key=private_key)
    
    assert "signature" in signed
    assert "payload_hash" in signed
    assert signed["prev_hash"] is None
    assert signed["chain_index"] == 0
    
    assert verify_decision(signed, public_key) is True


def test_canonical_json_is_deterministic(sample_decision):
    d1 = copy.deepcopy(sample_decision)
    d2 = copy.deepcopy(sample_decision)
    
    d1["z_field"] = "a"
    d1["a_field"] = "b"
    
    d2["a_field"] = "b"
    d2["z_field"] = "a"
    
    bytes1 = canonical_json(d1)
    bytes2 = canonical_json(d2)
    
    assert bytes1 == bytes2
    
    d1["signature"] = "ignored"
    d2["payload_hash"] = "also_ignored"
    
    assert canonical_json(d1) == canonical_json(d2)


def test_chain_breaks_on_tamper(sample_decision):
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    d1 = copy.deepcopy(sample_decision)
    s1 = sign_decision(d1, prev_hash=None, signing_key=private_key)
    
    d2 = copy.deepcopy(sample_decision)
    d2["chain_index"] = 1
    s2 = sign_decision(d2, prev_hash=s1["payload_hash"], signing_key=private_key)
    
    d3 = copy.deepcopy(sample_decision)
    d3["chain_index"] = 2
    s3 = sign_decision(d3, prev_hash=s2["payload_hash"], signing_key=private_key)
    
    chain = [s1, s2, s3]
    
    is_valid, broken_idx = verify_chain(chain, public_key)
    assert is_valid is True
    assert broken_idx is None
    
    chain[1]["action"] = "alert"
    
    is_valid, broken_idx = verify_chain(chain, public_key)
    assert is_valid is False
    assert broken_idx == 1


def test_chain_breaks_on_missing_link(sample_decision):
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    chain = []
    prev_hash = None
    for i in range(5):
        d = copy.deepcopy(sample_decision)
        d["chain_index"] = i
        s = sign_decision(d, prev_hash=prev_hash, signing_key=private_key)
        chain.append(s)
        prev_hash = s["payload_hash"]
        
    is_valid, broken_idx = verify_chain(chain, public_key)
    assert is_valid is True
    
    chain.pop(2)
    
    is_valid, broken_idx = verify_chain(chain, public_key)
    assert is_valid is False
    assert broken_idx == 2


def test_replay_produces_same_signature(sample_decision):
    private_key = ed25519.Ed25519PrivateKey.generate()
    
    s1 = sign_decision(sample_decision, prev_hash="abcdef", signing_key=private_key)
    s2 = sign_decision(sample_decision, prev_hash="abcdef", signing_key=private_key)
    
    assert s1["signature"] == s2["signature"]
    assert s1["payload_hash"] == s2["payload_hash"]


def test_different_key_produces_different_signature(sample_decision):
    k1 = ed25519.Ed25519PrivateKey.generate()
    k2 = ed25519.Ed25519PrivateKey.generate()
    
    s1 = sign_decision(sample_decision, prev_hash=None, signing_key=k1)
    s2 = sign_decision(sample_decision, prev_hash=None, signing_key=k2)
    
    assert s1["signature"] != s2["signature"]


def test_verify_with_wrong_public_key_fails(sample_decision):
    k1 = ed25519.Ed25519PrivateKey.generate()
    k2 = ed25519.Ed25519PrivateKey.generate()
    
    s1 = sign_decision(sample_decision, prev_hash=None, signing_key=k1)
    
    assert verify_decision(s1, k1.public_key()) is True
    assert verify_decision(s1, k2.public_key()) is False
