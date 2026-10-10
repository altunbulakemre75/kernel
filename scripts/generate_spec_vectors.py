"""Write the test vectors of docs/verification-spec.md to tests/fixtures/spec/.

The vectors are deterministic: a fixed Ed25519 test key (seed bytes 00..1f),
fixed timestamps and a relative policy path, so Ed25519's deterministic
signatures give the same chain on every machine. tests/test_spec_vectors.py
regenerates them and fails if they or the spec drift from the implementation.

    python scripts/generate_spec_vectors.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402

from kyvern import record_decision  # noqa: E402
from services.decision.policy_loader import clear_policy_cache  # noqa: E402

OUT = REPO_ROOT / "tests" / "fixtures" / "spec"
SEED = bytes(range(32))  # a published test key: never use it for real records
POLICY = """\
# Policy of the spec test vectors.
rules:
  - id: stop-on-obstacle
    action: stop
    below_m: 0.5
  - id: clear-path
    action: continue
"""


def test_key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(SEED)


def build(out: Path) -> None:
    """Write policy.yaml, signing.pub and chain.jsonl to `out` (replacing them)."""
    out.mkdir(parents=True, exist_ok=True)
    (out / "policy.yaml").write_bytes(POLICY.encode("utf-8"))
    (out / "signing.pub").write_bytes(test_key().public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    chain = out / "chain.jsonl"
    chain.unlink(missing_ok=True)
    clear_policy_cache()
    cwd = Path.cwd()
    os.chdir(out)  # the recorded policy_path is relative: "policy.yaml"
    try:
        record_decision(
            "stop", source="safety_controller",
            reasoning="obstacle at 0.4 m, closer than 0.5 m",
            inputs={"min_range_m": 0.4, "site": "Montréal"},
            rule_id="stop-on-obstacle", subject_id="amr-01",
            policy_path="policy.yaml", chain_path=chain, signing_key=test_key(),
            timestamp_iso="2026-10-07T12:00:00+00:00",
        )
        record_decision(
            "continue", source="operator",
            reasoning="operator removed the obstacle",
            inputs={"ticket": "OPS-1042"}, subject_id="amr-01",
            policy_path="policy.yaml", chain_path=chain, signing_key=test_key(),
            timestamp_iso="2026-10-07T12:00:05+00:00",
        )
    finally:
        os.chdir(cwd)


if __name__ == "__main__":
    build(OUT)
    print(f"wrote {OUT}")
