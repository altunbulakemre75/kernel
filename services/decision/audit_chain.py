import base64
import hashlib
import json
import os
from typing import Any, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

def load_or_create_keypair() -> ed25519.Ed25519PrivateKey:
    keys_dir = os.path.expanduser("~/.kernel/keys")
    priv_path = os.path.join(keys_dir, "signing.key")
    pub_path = os.path.join(keys_dir, "signing.pub")
    
    if os.path.exists(priv_path):
        with open(priv_path, "rb") as f:
            priv_bytes = f.read()
        return serialization.load_pem_private_key(priv_bytes, password=None)
    
    private_key = ed25519.Ed25519PrivateKey.generate()
    
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    os.makedirs(keys_dir, exist_ok=True)
    with open(priv_path, "wb") as f:
        f.write(priv_bytes)
    os.chmod(priv_path, 0o600)
    
    with open(pub_path, "wb") as f:
        f.write(pub_bytes)
        
    return private_key

def canonical_json(decision: dict[str, Any]) -> bytes:
    clean_dict = {k: v for k, v in decision.items() if k not in ("signature", "payload_hash")}
    return json.dumps(clean_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")

def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()

def sign_decision(decision: dict[str, Any], prev_hash: str | None, signing_key: ed25519.Ed25519PrivateKey) -> dict[str, Any]:
    signed_decision = decision.copy()
    signed_decision["prev_hash"] = prev_hash
    signed_decision["chain_index"] = decision.get("chain_index", 0)
    
    payload = canonical_json(signed_decision)
    payload_hash = sha256_hex(payload)
    
    sig = signing_key.sign(payload)
    
    signed_decision["payload_hash"] = payload_hash
    signed_decision["signature"] = base64.b64encode(sig).decode("utf-8")
    
    return signed_decision

def verify_decision(decision: dict[str, Any], public_key: ed25519.Ed25519PublicKey) -> bool:
    try:
        signature = decision.get("signature")
        if not signature:
            return False
            
        payload = canonical_json(decision)
        if decision.get("payload_hash") != sha256_hex(payload):
            return False
            
        sig_bytes = base64.b64decode(signature)
        public_key.verify(sig_bytes, payload)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False

def verify_chain(decisions: list[dict[str, Any]], public_key: ed25519.Ed25519PublicKey) -> Tuple[bool, int | None]:
    if not decisions:
        return True, None
        
    prev_hash = None
    expected_index = decisions[0].get("chain_index", 0)
    
    for i, decision in enumerate(decisions):
        if decision.get("chain_index") != expected_index:
            return False, i
            
        if decision.get("prev_hash") != prev_hash:
            return False, i
            
        if not verify_decision(decision, public_key):
            return False, i
            
        prev_hash = decision.get("payload_hash")
        expected_index += 1
        
    return True, None

def verify_decision_against_policy(decision: dict[str, Any], policy_path: str, public_key: ed25519.Ed25519PublicKey) -> Tuple[bool, str]:
    from services.decision.policy_loader import load_policy
    
    if not verify_decision(decision, public_key):
        return False, "Invalid decision signature"
        
    try:
        policy = load_policy(policy_path)
    except Exception as e:
        return False, f"Failed to load policy: {e}"
        
    decision_policy_version = decision.get("policy_version_id")
    if not decision_policy_version:
        return False, "Decision does not contain a policy_version_id"
        
    if policy.version_id != decision_policy_version:
        return False, f"Policy version mismatch: decision has {decision_policy_version}, loaded policy has {policy.version_id}"
        
    return True, "Match"
