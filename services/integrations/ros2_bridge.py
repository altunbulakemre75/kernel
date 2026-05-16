"""ROS2 bridge for kernel Decision objects.

Publishes cryptographically signed Decision dicts to a std_msgs/String
topic as canonical JSON. Using String-with-JSON rather than a custom
message type means any ROS2 node in any language can subscribe and parse
without depending on a custom kernel_msgs package.

rclpy is imported lazily (inside methods) so this module is importable
on non-ROS hosts (Windows, CI without ROS2).
"""
import json
from typing import Any


def decision_to_ros2_json(decision: dict[str, Any]) -> str:
    return json.dumps(decision, sort_keys=True, separators=(",", ":"))


class KernelDecisionPublisher:
    def __init__(
        self,
        node_name: str = "kernel_decision_publisher",
        topic: str = "/kernel/decisions",
        qos_reliability: str = "reliable",
    ) -> None:
        self.node_name = node_name
        self.topic = topic
        self.qos_reliability = qos_reliability
        self._node = None
        self._pub = None
        self._initialized_rclpy = False

    def start(self) -> None:
        import rclpy
        from rclpy.node import Node
        from rclpy.qos import QoSProfile, QoSReliabilityPolicy
        from std_msgs.msg import String

        if not rclpy.ok():
            rclpy.init()
            self._initialized_rclpy = True

        self._node = Node(self.node_name)

        qos = QoSProfile(depth=10)
        if self.qos_reliability == "best_effort":
            qos.reliability = QoSReliabilityPolicy.BEST_EFFORT
        else:
            qos.reliability = QoSReliabilityPolicy.RELIABLE

        self._pub = self._node.create_publisher(String, self.topic, qos)

    def publish(self, decision: dict[str, Any]) -> None:
        from std_msgs.msg import String

        msg = String()
        msg.data = decision_to_ros2_json(decision)
        self._pub.publish(msg)
        self._node.get_logger().info(
            f"Published decision chain_index={decision.get('chain_index')} "
            f"action={decision.get('action')}"
        )

    def stop(self) -> None:
        if self._node is not None:
            self._node.destroy_node()
            self._node = None
        if self._initialized_rclpy:
            import rclpy
            rclpy.shutdown()
            self._initialized_rclpy = False
