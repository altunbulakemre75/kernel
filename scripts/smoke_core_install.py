"""Smoke test for a core-only install (`pip install .`, no extras).

Run it from outside the repository so imports resolve to the installed package:

    cd /tmp && python <repo>/scripts/smoke_core_install.py

It runs one decision through the live pipeline into a temporary chain, verifies
the chain, and runs the CLIs' --help. It fails if any of that needs an extra.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        os.environ["HOME"] = str(home)         # Path.home() on POSIX
        os.environ["USERPROFILE"] = str(home)  # Path.home() on Windows
        chain = home / "chain.jsonl"

        import cli.kyvern_anchor  # noqa: F401
        import cli.kyvern_report  # noqa: F401
        import cli.kyvern_verify  # noqa: F401
        from services.decision.audit_chain import Keyring, verify_chain
        from services.decision.schemas import Action, ROERule, ThreatLevel
        from services.decision.threat_graph import decide_full

        rules = [
            ROERule(rule_id=f"r_{level.value}", description="smoke", when_threat_level=level,
                    requires_operator_approval=False, action=Action.LOG)
            for level in ThreatLevel
        ]
        track = {
            "track_id": "smoke", "latitude": 40.0, "longitude": 33.0, "altitude": 100.0,
            "confidence": 0.9, "hits": 10, "vx": 5.0, "vy": 0.0, "vz": 0.0,
            "x": 0.0, "y": 0.0, "z": 100.0, "sources": ["camera"],
        }
        decision = decide_full(track, rules, chain_path=chain)
        entries = [json.loads(line) for line in chain.read_text(encoding="utf-8").splitlines()]
        keys = Keyring.from_pem_files([home / ".kyvern" / "keys" / "signing.pub"])
        if verify_chain(entries, keys) != (True, None) or decision.chain_index != 0:
            print("smoke: the recorded decision does not verify", file=sys.stderr)
            return 1

        bin_dir = Path(sys.executable).parent
        for command in ("kyvern-verify", "kyvern-report", "kyvern-anchor"):
            subprocess.run([str(bin_dir / command), "--help"], check=True, capture_output=True)

    print("core install OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
