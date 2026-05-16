import json
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from services.decision.audit_chain import sign_decision
from services.integrations.ros2_bridge import KernelDecisionPublisher, decision_to_ros2_json


def _signed(policy_version_id: str = "abc123"):
    sk = ed25519.Ed25519PrivateKey.generate()
    d = {
        "track_id": "t0",
        "action": "allow",
        "threat_level": "low",
        "confidence": 0.9,
        "reasoning": "test",
        "source": "rule_engine",
        "roe_reference": "rule_1",
        "requires_operator_approval": False,
        "timestamp_iso": datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat(),
        "llm_raw_response": None,
        "llm_provider": None,
        "llm_model": None,
        "guardrails_triggered": [],
        "guardrail_reasoning": "",
        "policy_version_id": policy_version_id,
        "policy_path": "test.yaml",
        "chain_index": 0,
    }
    return sign_decision(d, prev_hash=None, signing_key=sk)


def test_serialization_includes_all_audit_fields():
    decision = _signed()
    data = json.loads(decision_to_ros2_json(decision))
    for field in (
        "signature", "payload_hash", "prev_hash", "chain_index",
        "policy_version_id", "action", "roe_reference", "timestamp_iso",
    ):
        assert field in data, f"Missing required audit field: {field}"


def test_serialization_is_deterministic():
    decision = _signed()
    assert decision_to_ros2_json(decision) == decision_to_ros2_json(decision)


def test_serialization_handles_none_values():
    decision = _signed()
    assert decision["prev_hash"] is None
    data = json.loads(decision_to_ros2_json(decision))
    assert data["prev_hash"] is None


def test_publisher_initialization_does_not_require_rclpy():
    pub = KernelDecisionPublisher()
    assert pub.node_name == "kernel_decision_publisher"
    assert pub.topic == "/kernel/decisions"
    assert pub.qos_reliability == "reliable"


def test_publisher_start_stop():
    pytest.importorskip("rclpy")
    pub = KernelDecisionPublisher(node_name="test_pub")
    pub.start()
    pub.stop()
