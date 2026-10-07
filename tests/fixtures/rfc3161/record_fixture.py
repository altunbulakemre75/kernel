"""Record the offline RFC 3161 fixture used by the anchoring tests.

Run once from the repo root:  python tests/fixtures/rfc3161/record_fixture.py
It creates a test-only key pair, a two-entry chain signed with it, and a real
IdenTrust timestamp for the chain head. Only the hash of the anchor statement
is sent to the TSA. Re-running overwrites the fixture.
"""
from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from services.decision.anchors import anchor_head, anchors_path_for
from services.decision.chain_writer import ChainWriter
from services.decision.policy_loader import load_policy
from services.decision.rfc3161_anchor import RFC3161Anchor

HERE = Path(__file__).parent
POLICY = """rules:
  - rule_id: "rule_1"
    description: "Fixture policy"
    when_threat_level: "low"
    requires_operator_approval: false
    action: "log"
    enabled: true
"""


def main() -> None:
    (HERE / "policy.yaml").write_text(POLICY, encoding="utf-8")
    policy = load_policy(str(HERE / "policy.yaml"))

    key = ed25519.Ed25519PrivateKey.generate()
    (HERE / "signing.key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    (HERE / "signing.pub").write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

    chain = HERE / "chain.jsonl"
    for path in (chain, anchors_path_for(chain)):
        path.unlink(missing_ok=True)
    writer = ChainWriter(chain, key)
    for i in range(2):
        writer.append({
            "track_id": f"fixture_{i}", "action": "log", "threat_level": "low",
            "confidence": 0.9, "reasoning": "fixture", "source": "rule_engine",
            "roe_reference": "rule_1", "requires_operator_approval": False,
            "timestamp_iso": f"2026-10-07T12:00:0{i}+00:00",
            "llm_raw_response": None, "llm_provider": None, "llm_model": None,
            "guardrails_triggered": [], "guardrail_reasoning": "",
            "policy_version_id": policy.version_id, "policy_path": "policy.yaml",
        })
    receipt = anchor_head(chain, RFC3161Anchor())
    print(f"recorded receipt for chain_index {receipt['chain_index']} at {receipt['anchored_at']}")


if __name__ == "__main__":
    main()
