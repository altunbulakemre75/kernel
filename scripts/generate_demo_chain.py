"""One-shot demo data generator for kernel-verify.

Not for commit. Writes a signed decision chain plus a tampered copy
under <system tmp>/kernel-demo/ for manual CLI exercises.
"""
import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402

from services.decision.audit_chain import sign_decision  # noqa: E402
from services.decision.policy_loader import clear_policy_cache, load_policy  # noqa: E402

POLICY_PATH = "config/policies/default.yaml"
# tempfile.gettempdir() matches bash's /tmp on this Windows host
# (C:\Users\<user>\AppData\Local\Temp) and equals /tmp on POSIX.
DEMO_DIR = Path(tempfile.gettempdir()) / "kernel-demo"


def main() -> None:
    DEMO_DIR.mkdir(parents=True, exist_ok=True)

    private_key = ed25519.Ed25519PrivateKey.generate()
    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (DEMO_DIR / "signing.pub").write_bytes(pub_bytes)

    clear_policy_cache()
    policy = load_policy(str(REPO_ROOT / POLICY_PATH))

    spec = [
        ("allow", "low",    "r_001", False, []),
        ("alert", "medium", "r_003", False, ["geofence"]),
        ("allow", "low",    "r_001", False, []),
        ("halt",  "high",   "r_007", True,  ["downgrade_from_engage"]),
        ("allow", "low",    "r_001", False, []),
    ]
    base_ts = datetime(2026, 5, 16, 14, 32, 7, tzinfo=timezone.utc)

    chain = []
    prev_hash = None
    for i, (action, threat, rule_id, approval, guardrails) in enumerate(spec):
        ts = base_ts + timedelta(seconds=5 * i)
        decision = {
            "track_id": f"demo_{i}",
            "action": action,
            "threat_level": threat,
            "confidence": 0.92,
            "reasoning": "demo scenario",
            "source": "rule_engine",
            "roe_reference": rule_id,
            "requires_operator_approval": approval,
            "timestamp_iso": ts.isoformat(),
            "llm_raw_response": None,
            "llm_provider": None,
            "llm_model": None,
            "guardrails_triggered": guardrails,
            "guardrail_reasoning": "",
            "policy_version_id": policy.version_id,
            "policy_path": POLICY_PATH,
            "chain_index": i,
        }
        signed = sign_decision(decision, prev_hash=prev_hash, signing_key=private_key)
        chain.append(signed)
        prev_hash = signed["payload_hash"]

    chain_path = DEMO_DIR / "chain.jsonl"
    with chain_path.open("w", encoding="utf-8") as f:
        for d in chain:
            f.write(json.dumps(d) + "\n")

    tampered = [dict(d) for d in chain]
    tampered[3]["action"] = "allow"
    tampered_path = DEMO_DIR / "chain_tampered.jsonl"
    with tampered_path.open("w", encoding="utf-8") as f:
        for d in tampered:
            f.write(json.dumps(d) + "\n")

    print(
        "Demo files created. Run these to see the verification:\n"
        "\n"
        "python -m cli.kernel_verify /tmp/kernel-demo/chain.jsonl \\\n"
        "    --policy config/policies/default.yaml \\\n"
        "    --pubkey /tmp/kernel-demo/signing.pub\n"
        "\n"
        "python -m cli.kernel_verify /tmp/kernel-demo/chain_tampered.jsonl \\\n"
        "    --policy config/policies/default.yaml \\\n"
        "    --pubkey /tmp/kernel-demo/signing.pub"
    )


if __name__ == "__main__":
    main()
