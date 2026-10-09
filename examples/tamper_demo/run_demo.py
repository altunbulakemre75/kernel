"""Four ways to tamper with a robot's decision log, and what catches each one.

A warehouse robot (amr-01) records its own safety decisions with Kyvern, as in
examples/ros2_safety_demo, and the log is anchored with an RFC 3161 Time
Stamping Authority. Each attack then works on a copy of that log, and
kyvern-verify decides:

  1. someone edits a decision in the file          -> caught by the signatures
  2. an insider holding the signing key rewrites   -> caught by the RFC 3161 receipt
     a decision and re-signs everything after it
  3. an insider deletes the latest decisions       -> caught by the RFC 3161 receipt
  4. an insider adds a decision dated a month ago  -> caught by --max-lag
     and anchors it

    python examples/tamper_demo/run_demo.py [--out DIR] [--offline]

Attacks 2-4 need receipts from a public Time Stamping Authority (IdenTrust by
default; only a SHA-256 hash leaves the machine). --offline runs attack 1 only.
Exits 0 when the untouched log verifies and every attack is caught.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SAFETY_DEMO = ROOT / "examples" / "ros2_safety_demo"
POLICY = SAFETY_DEMO / "safety_policy.yaml"
sys.path.insert(0, str(SAFETY_DEMO))
if (ROOT / "cli").is_dir():  # running from a clone: no install needed
    sys.path.insert(0, str(ROOT))

from safety_controller import SafetyController  # noqa: E402

from kyvern import record_decision  # noqa: E402
from services.decision.audit_chain import sign_decision  # noqa: E402

APPROACH_M = [3.0, 2.4, 1.8, 1.4, 1.0, 0.7, 0.45, 0.3]  # closest obstacle, scan by scan
AFTER_RESUME_M = [2.5, 2.8]
MAX_LAG = "1h"


def _cli(module: str, *args: object) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ, PYTHONUTF8="1")
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(ROOT), env.get("PYTHONPATH")]))
    return subprocess.run(
        [sys.executable, "-m", module, *map(str, args)],
        capture_output=True, text=True, encoding="utf-8", env=env,
    )


def _read(chain: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in chain.read_text(encoding="utf-8").splitlines() if line]


def _write(chain: Path, entries: list[dict[str, Any]]) -> None:
    chain.write_text("".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8")


def _resign(entries: list[dict[str, Any]], start: int, key: ed25519.Ed25519PrivateKey) -> None:
    """What an insider with the key does: re-sign entries[start:] so the hash links hold."""
    prev = entries[start - 1]["payload_hash"] if start else None
    for i in range(start, len(entries)):
        unsigned = {k: v for k, v in entries[i].items()
                    if k not in ("signature", "payload_hash", "key_id")}
        entries[i] = sign_decision(unsigned, prev_hash=prev, signing_key=key)
        prev = entries[i]["payload_hash"]


def record_scenario(chain: Path, key: ed25519.Ed25519PrivateKey) -> None:
    """amr-01 approaches an obstacle, stops, is resumed by an operator, drives on."""
    controller = SafetyController(POLICY, chain_path=chain, signing_key=key)
    for closest in APPROACH_M:
        controller.on_scan(closest, "amr-01")
    record_decision(
        "continue", source="operator",
        reasoning="operator removed the obstacle and resumed the robot",
        inputs={"ticket": "OPS-1042"}, subject_id="amr-01",
        policy_path=POLICY, chain_path=chain, signing_key=key,
    )
    for closest in AFTER_RESUME_M:
        controller.on_scan(closest, "amr-01")


# ── Attacks: each changes a copy of the log in place ──────────────────────────

def _first_stop(entries: list[dict[str, Any]]) -> int:
    return next(i for i, e in enumerate(entries) if e.get("action") == "stop")


def edit_a_decision(chain: Path, key: ed25519.Ed25519PrivateKey) -> str:
    entries = _read(chain)
    i = _first_stop(entries)
    entries[i]["action"] = "continue"
    _write(chain, entries)
    return f"changes decision {i} from STOP to CONTINUE in the file"


def rewrite_and_resign(chain: Path, key: ed25519.Ed25519PrivateKey) -> str:
    entries = _read(chain)
    i = _first_stop(entries)
    entries[i]["action"] = "continue"
    _resign(entries, i, key)
    _write(chain, entries)
    return f"changes decision {i} from STOP to CONTINUE and re-signs it and every later one"


def delete_the_latest(chain: Path, key: ed25519.Ed25519PrivateKey) -> str:
    entries = _read(chain)
    _write(chain, entries[:-2])
    return f"deletes the last 2 of {len(entries)} decisions"


def add_a_backdated_decision(chain: Path, key: ed25519.Ed25519PrivateKey) -> str:
    month_ago = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    record_decision(
        "continue", source="operator",
        reasoning="safety check passed", inputs={"ticket": "OPS-0999"}, subject_id="amr-01",
        policy_path=POLICY, chain_path=chain, signing_key=key, timestamp_iso=month_ago,
    )
    anchored = _cli("cli.kyvern_anchor", chain)
    if anchored.returncode:
        raise RuntimeError(anchored.stderr.strip())
    return "appends a decision dated 30 days ago, signs it and anchors it today"


ATTACKS: list[tuple[str, Callable[[Path, ed25519.Ed25519PrivateKey], str], bool]] = [
    # (name, attack, needs receipts)
    ("Edit a decision in the file", edit_a_decision, False),
    ("Insider rewrites a decision and re-signs", rewrite_and_resign, True),
    ("Insider deletes the latest decisions", delete_the_latest, True),
    ("Insider adds a backdated decision", add_a_backdated_decision, True),
]


def verify(chain: Path, pubkey: Path, *, anchored: bool) -> dict[str, Any]:
    args: list[object] = [chain, "--policy", POLICY, "--pubkey", pubkey, "--json"]
    if anchored:
        args += ["--require-anchors", "--max-lag", MAX_LAG]
    res = _cli("cli.kyvern_verify", *args)
    try:
        result = json.loads(res.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"kyvern-verify gave no JSON: {res.stderr.strip()}") from exc
    result["exit_code"] = res.returncode
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default="kyvern-tamper-demo", help="output directory")
    parser.add_argument("--offline", action="store_true",
                        help="no Time Stamping Authority: run attack 1 only")
    args = parser.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):  # ✓ and ✗ on a Windows code page
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8")

    out = Path(args.out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    key = ed25519.Ed25519PrivateKey.generate()
    pubkey = out / "signing.pub"
    pubkey.write_bytes(key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    original = out / "original" / "chain.jsonl"
    original.parent.mkdir()
    record_scenario(original, key)
    anchored = not args.offline
    if anchored:
        res = _cli("cli.kyvern_anchor", original)
        if res.returncode:
            print(f"Could not reach the Time Stamping Authority: {res.stderr.strip()}\n"
                  "Run with --offline to try attack 1 only.", file=sys.stderr)
            return 2

    entries = _read(original)
    print(f"Robot amr-01 recorded {len(entries)} safety decisions "
          + ("and anchored the log with an RFC 3161 Time Stamping Authority." if anchored
             else "(offline: no RFC 3161 receipts)."))
    baseline = verify(original, pubkey, anchored=anchored)
    ok = baseline["exit_code"] == 0
    print(f"\n{'✓' if ok else '✗'} Untouched log: "
          + ("verifies" if ok else "DOES NOT VERIFY: " + "; ".join(baseline["errors"])))

    caught = 0
    attacks = [a for a in ATTACKS if anchored or not a[2]]
    for n, (name, attack, _) in enumerate(attacks, start=1):
        copy = out / f"attack-{n}" / "chain.jsonl"
        shutil.copytree(original.parent, copy.parent)
        what = attack(copy, key)
        result = verify(copy, pubkey, anchored=anchored)
        if result["exit_code"] == 1:
            caught += 1
        # The same tampered log checked by signatures alone, without receipts or --max-lag.
        bare = out / f"attack-{n}" / "signatures-only" / "chain.jsonl"
        bare.parent.mkdir()
        shutil.copy(copy, bare)
        signatures_only = verify(bare, pubkey, anchored=False)
        print(f"\n{'✓ CAUGHT' if result['exit_code'] == 1 else '✗ MISSED'}  {n}. {name}")
        print(f"    attack:          {what}")
        print("    signatures only: "
              + ("caught too" if signatures_only["exit_code"] == 1 else "would PASS"))
        print(f"    kyvern-verify:   {result['errors'][0] if result['errors'] else 'passed'}")

    print(f"\n{caught} of {len(attacks)} attacks caught. Files: {out.resolve()}")
    if anchored:
        report = _cli("cli.kyvern_report", original, "--policy", POLICY, "--pubkey", pubkey,
                      "--output", out / "report.pdf", "--system-id", "amr-01")
        if report.returncode == 0:
            print(f"Evidence report for the untouched log: {(out / 'report.pdf').resolve()}")
    return 0 if ok and caught == len(attacks) else 1


if __name__ == "__main__":
    sys.exit(main())
