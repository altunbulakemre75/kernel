# ROS2 Integration

## Why this bridge exists

kernel produces cryptographically signed `Decision` objects tied to a
tamper-evident hash chain. This bridge publishes each Decision to a
ROS2 topic so any ROS2 node — controller, logger, HMI — can consume
decisions natively without coupling to the kernel Python API.

## Quick start

**Prerequisites:** ROS2 Humble installed and sourced (`source /opt/ros/humble/setup.bash`).

**Publish decisions:**

```python
from services.integrations.ros2_bridge import KernelDecisionPublisher

pub = KernelDecisionPublisher(topic="/kernel/decisions")
pub.start()
pub.publish(signed_decision)   # signed_decision is a dict from sign_decision()
pub.stop()
```

**Subscribe and verify:**

```python
from services.integrations.ros2_subscriber_example import KernelDecisionVerifier

verifier = KernelDecisionVerifier(public_key_path="/tmp/kernel-demo/signing.pub")
verifier.start()   # blocks; Ctrl-C to stop
```

Or run the subscriber standalone:

```bash
python -m services.integrations.ros2_subscriber_example \
    --pubkey /tmp/kernel-demo/signing.pub
```

## Message format

Topic type: `std_msgs/String`

Payload: canonical JSON produced by `decision_to_ros2_json(decision)`.
Field order is alphabetical (`sort_keys=True`) for determinism.

Key fields:

| Field | Type | Description |
|---|---|---|
| `action` | string | Decision action (allow / alert / halt / handoff / engage) |
| `chain_index` | int | Position in the hash chain |
| `payload_hash` | string | SHA-256 of canonical payload (hex) |
| `prev_hash` | string \| null | Hash of preceding decision; null for chain head |
| `policy_version_id` | string | SHA-256 of the policy file at decision time |
| `roe_reference` | string | Rule ID that fired |
| `signature` | string | Base64 Ed25519 signature |
| `timestamp_iso` | string | ISO 8601 UTC timestamp |

**Why not a custom message type?** A custom `kernel_msgs/Decision.msg`
would require every subscriber to build and source the `kernel_msgs`
package. `std_msgs/String` with JSON means a Python, C++, or Rust
subscriber can parse the payload with a single `json.loads` call,
with no build-time kernel dependency.

## QoS recommendations

| Scenario | Setting |
|---|---|
| Safety-critical decisions (halt, handoff, engage) | `qos_reliability="reliable"` (default) |
| High-frequency telemetry / allow decisions | `qos_reliability="best_effort"` |

```python
pub = KernelDecisionPublisher(qos_reliability="best_effort")
```

## End-to-end test (WSL + ROS2 Humble)

First generate demo files:

```bash
python scripts/generate_demo_chain.py
```

**Terminal 1 — subscriber:**

```bash
source /opt/ros/humble/setup.bash
python -m services.integrations.ros2_subscriber_example \
    --pubkey /tmp/kernel-demo/signing.pub
```

**Terminal 2 — publish one decision from the demo chain:**

```bash
source /opt/ros/humble/setup.bash
python -c "
import json
from services.integrations.ros2_bridge import KernelDecisionPublisher

chain = [json.loads(l) for l in open('/tmp/kernel-demo/chain.jsonl')]
pub = KernelDecisionPublisher()
pub.start()
pub.publish(chain[0])
pub.stop()
"
```

Terminal 1 should log: `[VERIFIED] chain_index=0`
