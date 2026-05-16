"""Reference ROS2 subscriber for kernel Decision messages.

Parses the JSON payload and verifies the Ed25519 signature on each
received decision. Prints [VERIFIED] or [REJECTED] with chain_index.

Run standalone:
    python -m services.integrations.ros2_subscriber_example \\
        --pubkey /tmp/kernel-demo/signing.pub
"""
import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))


def _load_pubkey(path: str):
    from cryptography.hazmat.primitives import serialization

    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


class KernelDecisionVerifier:
    def __init__(
        self,
        public_key_path: str,
        node_name: str = "kernel_decision_verifier",
        topic: str = "/kernel/decisions",
    ) -> None:
        self.public_key = _load_pubkey(public_key_path)
        self.node_name = node_name
        self.topic = topic
        self._node = None

    def start(self) -> None:
        import rclpy
        from rclpy.node import Node
        from std_msgs.msg import String

        rclpy.init()
        self._node = Node(self.node_name)
        self._node.create_subscription(String, self.topic, self._callback, 10)
        rclpy.spin(self._node)

    def _callback(self, msg: Any) -> None:
        from services.decision.audit_chain import verify_decision

        try:
            decision = json.loads(msg.data)
        except json.JSONDecodeError:
            self._node.get_logger().error("Received non-JSON message on topic")
            return

        idx = decision.get("chain_index", "?")
        if verify_decision(decision, self.public_key):
            self._node.get_logger().info(f"[VERIFIED] chain_index={idx}")
        else:
            self._node.get_logger().warn(f"[REJECTED] chain_index={idx}")

    def stop(self) -> None:
        if self._node is not None:
            self._node.destroy_node()
            self._node = None
        import rclpy

        if rclpy.ok():
            rclpy.shutdown()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Verify kernel decisions received on a ROS2 topic"
    )
    parser.add_argument("--pubkey", required=True, help="Path to PEM public key")
    parser.add_argument("--topic", default="/kernel/decisions", help="ROS2 topic name")
    args = parser.parse_args()

    verifier = KernelDecisionVerifier(args.pubkey, topic=args.topic)
    try:
        verifier.start()
    finally:
        verifier.stop()
