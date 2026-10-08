"""ROS2 node: the safety controller on a real (or simulated) robot.

Subscribes to /scan (sensor_msgs/LaserScan), decides stop / slow / continue
with SafetyController, records each change of action with Kyvern, and
publishes the action on /safety/action (std_msgs/String) for the motion layer.

With ROS2 sourced and Kyvern installed (`pip install .` from the repository):

    python examples/ros2_safety_demo/ros2_node.py --ros-args -p subject_id:=amr-01

Decisions go to the default chain (~/.kyvern/chain.jsonl, or $KYVERN_CHAIN_PATH),
signed with ~/.kyvern/keys/signing.key.
"""
from __future__ import annotations

import sys
from pathlib import Path

from safety_controller import SafetyController, min_valid_range


def main(argv: list[str] | None = None) -> None:
    # Imported here so this module imports on hosts without ROS2 (tests, CI).
    import rclpy
    from rclpy.node import Node
    from sensor_msgs.msg import LaserScan
    from std_msgs.msg import String

    class SafetyNode(Node):
        def __init__(self) -> None:
            super().__init__("kyvern_safety_controller")
            policy = self.declare_parameter(
                "policy", str(Path(__file__).with_name("safety_policy.yaml")),
            ).value
            self.subject_id = self.declare_parameter("subject_id", "robot").value
            self.controller = SafetyController(policy)
            self.action_pub = self.create_publisher(String, "/safety/action", 10)
            self.create_subscription(LaserScan, "/scan", self.on_scan, 10)

        def on_scan(self, msg: LaserScan) -> None:
            closest = min_valid_range(msg.ranges, msg.range_min, msg.range_max)
            if closest is None:
                return
            decision = self.controller.on_scan(closest, subject_id=self.subject_id)
            self.action_pub.publish(String(data=decision.action))

    rclpy.init(args=argv)
    node = SafetyNode()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == "__main__":
    main(sys.argv)
