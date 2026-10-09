"""examples/tamper_demo: every attack on the robot's decision log is caught.

Offline, only the file edit runs; the insider attacks need RFC 3161 receipts
from IdenTrust and run with KYVERN_TSA_E2E=1.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

DEMO = Path(__file__).parent.parent.parent / "examples" / "tamper_demo" / "run_demo.py"


def _run(out: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ, PYTHONUTF8="1")
    return subprocess.run(
        [sys.executable, str(DEMO), "--out", str(out), *args],
        capture_output=True, text=True, encoding="utf-8", env=env,
    )


def test_offline_the_edited_decision_is_caught(tmp_path):
    res = _run(tmp_path / "demo", "--offline")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "✓ Untouched log: verifies" in res.stdout
    assert "✓ CAUGHT  1. Edit a decision in the file" in res.stdout
    assert "Chain integrity broken at index 2: bad signature" in res.stdout
    assert "1 of 1 attacks caught" in res.stdout


@pytest.mark.skipif(not os.environ.get("KYVERN_TSA_E2E"), reason="set KYVERN_TSA_E2E=1 to call IdenTrust")
def test_every_attack_is_caught_and_insiders_pass_signatures_alone(tmp_path):
    res = _run(tmp_path / "demo")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "4 of 4 attacks caught" in res.stdout
    assert res.stdout.count("signatures only: would PASS") == 3
    assert "does not match the anchored hash" in res.stdout
    assert "chain entry 4 is missing" in res.stdout
    assert "Anchor lag: entry 5 was first anchored 30d" in res.stdout
    assert (tmp_path / "demo" / "report.pdf").is_file()
