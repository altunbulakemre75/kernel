import base64
import copy

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from services.decision.audit_chain import (
    Keyring,
    canonical_json,
    describe_chain_failure,
    key_id,
    sha256_hex,
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


# ── key_id and Keyring ────────────────────────────────────────────────────────

def _chain(sample_decision, keys):
    chain, prev = [], None
    for i, key in enumerate(keys):
        signed = sign_decision(dict(sample_decision, chain_index=i), prev_hash=prev, signing_key=key)
        chain.append(signed)
        prev = signed["payload_hash"]
    return chain


def test_key_id_is_embedded_and_signed(sample_decision):
    key = ed25519.Ed25519PrivateKey.generate()
    signed = sign_decision(sample_decision, prev_hash=None, signing_key=key)
    assert signed["key_id"] == key_id(key.public_key())
    assert len(signed["key_id"]) == 16
    assert verify_decision(signed, key.public_key()) is True
    assert verify_decision(dict(signed, key_id="0" * 16), key.public_key()) is False


def test_keyring_verifies_a_chain_signed_by_two_keys(sample_decision):
    k1, k2 = ed25519.Ed25519PrivateKey.generate(), ed25519.Ed25519PrivateKey.generate()
    chain = _chain(sample_decision, [k1, k1, k2])
    assert verify_chain(chain, Keyring([k1.public_key(), k2.public_key()])) == (True, None)


def test_missing_key_is_reported_as_unknown(sample_decision):
    k1, k2 = ed25519.Ed25519PrivateKey.generate(), ed25519.Ed25519PrivateKey.generate()
    chain = _chain(sample_decision, [k1, k1, k2])
    only_k1 = Keyring([k1.public_key()])
    assert verify_chain(chain, only_k1) == (False, 2)
    assert verify_chain(chain, k1.public_key()) == (False, 2)
    assert describe_chain_failure(chain, 2, only_k1) == (
        f"signed by unknown key {key_id(k2.public_key())}"
    )


def test_record_without_key_id_still_verifies(sample_decision):
    key = ed25519.Ed25519PrivateKey.generate()
    legacy = dict(sample_decision, prev_hash=None, chain_index=0)  # signed the pre-0.3.0 way
    payload = canonical_json(legacy)
    legacy["payload_hash"] = sha256_hex(payload)
    legacy["signature"] = base64.b64encode(key.sign(payload)).decode()
    other = ed25519.Ed25519PrivateKey.generate().public_key()
    assert verify_decision(legacy, key.public_key()) is True
    assert verify_decision(legacy, Keyring([other, key.public_key()])) is True
    assert verify_decision(legacy, Keyring([other])) is False


def test_describe_chain_failure_names_each_reason(sample_decision):
    key = ed25519.Ed25519PrivateKey.generate()
    keys = Keyring([key.public_key()])

    gap = _chain(sample_decision, [key, key, key])
    gap[1]["chain_index"] = 5
    assert describe_chain_failure(gap, 1, keys).startswith("chain_index gap")

    link = _chain(sample_decision, [key, key, key])
    link[1]["prev_hash"] = "00" * 32
    assert describe_chain_failure(link, 1, keys) == "broken prev_hash link"

    tampered = _chain(sample_decision, [key, key, key])
    tampered[1]["reasoning"] = "rewritten"
    assert describe_chain_failure(tampered, 1, keys) == "bad signature"
