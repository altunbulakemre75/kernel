"""examples/ros2_safety_demo: a robot's own safety decisions, recorded and audited.

The controller and the scenario run without ROS2; the rclpy node is only
imported, since CI has no ROS2.
"""
from __future__ import annotations

import importlib.util
import json
import math
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from services.decision.audit_chain import verify_chain
from services.decision.policy_loader import clear_policy_cache, load_policy

DEMO_DIR = Path(__file__).parent.parent.parent / "examples" / "ros2_safety_demo"
POLICY = DEMO_DIR / "safety_policy.yaml"


def _load(name: str):
    """Import a module from the demo directory (it is an example, not a package)."""
    spec = importlib.util.spec_from_file_location(name, DEMO_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def demo(monkeypatch):
    clear_policy_cache()
    monkeypatch.syspath_prepend(str(DEMO_DIR))
    return _load("safety_controller")


def _entries(chain: Path) -> list[dict]:
    return [json.loads(line) for line in chain.read_text(encoding="utf-8").splitlines()]


@pytest.mark.parametrize(("min_range_m", "action", "rule_id"), [
    (0.3, "stop", "stop-on-obstacle"),
    (0.5, "slow", "slow-near-obstacle"),  # thresholds are strict: 0.5 is not < 0.5
    (1.2, "slow", "slow-near-obstacle"),
    (3.0, "continue", "clear-path"),
])
def test_the_controller_follows_the_policy(demo, min_range_m, action, rule_id):
    decision = demo.SafetyController(POLICY).decide(min_range_m)
    assert (decision.action, decision.rule_id) == (action, rule_id)
    assert decision.inputs == {"min_range_m": min_range_m}
    assert str(min_range_m) in decision.reasoning


def test_the_controller_records_each_change_of_action(demo, tmp_path):
    chain = tmp_path / "chain.jsonl"
    key = ed25519.Ed25519PrivateKey.generate()
    controller = demo.SafetyController(POLICY, chain_path=chain, signing_key=key)

    for r in (3.0, 2.5, 1.2, 1.0, 0.4, 0.3, 2.0):
        controller.on_scan(r, subject_id="amr-01")

    entries = _entries(chain)
    assert [e["action"] for e in entries] == ["continue", "slow", "stop", "continue"]
    assert {e["policy_version_id"] for e in entries} == {load_policy(str(POLICY)).version_id}
    assert {e["subject_id"] for e in entries} == {"amr-01"}
    assert verify_chain(entries, key.public_key()) == (True, None)


def test_min_valid_range_ignores_readings_outside_the_sensor_range(demo):
    ranges = [math.inf, 0.02, float("nan"), 1.7, 0.9, 40.0]
    assert demo.min_valid_range(ranges, range_min=0.05, range_max=30.0) == 0.9
    assert demo.min_valid_range([math.inf, math.nan], range_min=0.05, range_max=30.0) is None


def test_the_scenario_is_recorded_verified_and_reported(demo, tmp_path, capsys):
    pytest.importorskip("pypdf")
    run_demo = _load("run_demo")

    assert run_demo.main(["--out", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "Chain integrity: VALID" in out
    assert "source=operator" in out
    assert "[chain: VALID] [policy: OK]" in out
    assert (tmp_path / "report.pdf").read_bytes()[:5] == b"%PDF-"
    actions = [(e["action"], e["source"]) for e in _entries(tmp_path / "chain.jsonl")]
    assert actions == [
        ("continue", "safety_controller"), ("slow", "safety_controller"),
        ("stop", "safety_controller"), ("continue", "operator"),
        ("continue", "safety_controller"),
    ]


def test_the_ros2_node_imports_without_ros2(demo):
    node = _load("ros2_node")
    assert callable(node.main)
