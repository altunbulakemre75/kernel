"""Run the safety demo without ROS2.

A robot (amr-01) drives toward an obstacle: its own safety controller slows it,
then stops it. An operator removes the obstacle and resumes it, and the
controller sees a clear path again. Every decision is recorded with Kyvern;
the chain is then verified against the robot's policy and reported on.

    python examples/ros2_safety_demo/run_demo.py [--out DIR] [--anchor]

Writes chain.jsonl, signing.pub and report.pdf to DIR (default
./kyvern-safety-demo). It uses its own signing key, never ~/.kyvern. --anchor
also timestamps the chain head with an RFC 3161 authority (needs network).
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from safety_controller import SafetyController

from kyvern import record_decision

HERE = Path(__file__).resolve().parent
POLICY = HERE / "safety_policy.yaml"
APPROACH_M = [3.0, 2.4, 1.8, 1.4, 1.0, 0.7, 0.45, 0.3]  # closest obstacle, scan by scan
AFTER_RESUME_M = [2.5, 2.8]


def _cli(module: str, *args: object) -> int:
    """Run a Kyvern CLI and echo its output."""
    env = dict(os.environ)
    root = HERE.parent.parent
    if (root / "cli").is_dir():  # running from a clone: make `cli` importable without an install
        env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(root), env.get("PYTHONPATH")]))
    res = subprocess.run(
        [sys.executable, "-m", module, *map(str, args)], capture_output=True, text=True, env=env,
    )
    print(res.stdout, end="")
    print(res.stderr, end="", file=sys.stderr)
    return res.returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default="kyvern-safety-demo", help="output directory")
    parser.add_argument("--anchor", action="store_true",
                        help="timestamp the chain head with RFC 3161 (needs network)")
    args = parser.parse_args(argv)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    chain = out / "chain.jsonl"
    for stale in (chain, out / "chain.anchors.jsonl", out / "report.pdf"):
        stale.unlink(missing_ok=True)
    key = ed25519.Ed25519PrivateKey.generate()
    pubkey = out / "signing.pub"
    pubkey.write_bytes(key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))

    controller = SafetyController(POLICY, chain_path=chain, signing_key=key)
    print("Robot amr-01 drives toward an obstacle:")
    for closest in APPROACH_M:
        print(f"  closest obstacle {closest:4.2f} m -> {controller.on_scan(closest, 'amr-01').action}")
    print("An operator removes the obstacle and resumes the robot.")
    record_decision(
        "continue", source="operator",
        reasoning="operator removed the obstacle and resumed the robot",
        inputs={"ticket": "OPS-1042"}, subject_id="amr-01",
        policy_path=POLICY, chain_path=chain, signing_key=key,
    )
    for closest in AFTER_RESUME_M:
        print(f"  closest obstacle {closest:4.2f} m -> {controller.on_scan(closest, 'amr-01').action}")

    code = 0
    if args.anchor:
        print("\n$ kyvern-anchor")
        code |= _cli("cli.kyvern_anchor", chain)
    print("\n$ kyvern-verify")
    code |= _cli("cli.kyvern_verify", chain, "--policy", POLICY, "--pubkey", pubkey)
    print("\n$ kyvern-report")
    code |= _cli(
        "cli.kyvern_report", chain, "--policy", POLICY, "--pubkey", pubkey,
        "--output", out / "report.pdf", "--system-id", "amr-01",
    )
    return code


if __name__ == "__main__":
    sys.exit(main())
