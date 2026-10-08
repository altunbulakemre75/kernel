# Safety controller demo: a robot's own decisions, recorded and audited

A mobile robot's safety controller decides **stop**, **slow** or **continue**
from the closest obstacle in its laser scan. The decision logic is the
robot's own (`safety_controller.py`, thresholds in `safety_policy.yaml`);
Kyvern records each decision — what, why, on which reading, under which
version of the policy — into a signed chain that an auditor can verify
without trusting the robot's operator.

## Run it without ROS2

From a clone of the repository, after `pip install .`:

```bash
python examples/ros2_safety_demo/run_demo.py --out kyvern-safety-demo
```

The robot approaches an obstacle (slow at 1.4 m, stop at 0.45 m), an operator
removes the obstacle and resumes it, and the controller sees a clear path
again. The script then runs `kyvern-verify` and `kyvern-report`:

```text
Decision summary:
  [0] 10:11:01  action=CONTINUE rule_id=clear-path source=safety_controller
  [1] 10:11:01  action=SLOW     rule_id=slow-near-obstacle source=safety_controller
  [2] 10:11:01  action=STOP     rule_id=stop-on-obstacle source=safety_controller
  [3] 10:11:01  action=CONTINUE rule_id=None source=operator
  [4] 10:11:01  action=CONTINUE rule_id=clear-path source=safety_controller
```

`kyvern-safety-demo/` then holds `chain.jsonl`, the demo's public key
`signing.pub` and `report.pdf`. The demo signs with its own key and never
touches `~/.kyvern`. Add `--anchor` to timestamp the chain head with an
RFC 3161 authority (needs network); `kyvern-verify` then also checks the
receipt.

Things to try:

- Edit a recorded decision in `chain.jsonl` and run `kyvern-verify` again:
  the chain is reported broken at that entry.
- Change a threshold in `safety_policy.yaml` and verify against it: every
  decision is reported as bound to a policy that was not given.
- Read the report's Article 12 and 14 pages: each row is a check run on the
  chain; the operator's resume shows up as a recorded human intervention.

## Run it on a robot (ROS2)

With ROS2 sourced (`rclpy`, `sensor_msgs`, `std_msgs`) and Kyvern installed:

```bash
python examples/ros2_safety_demo/ros2_node.py --ros-args -p subject_id:=amr-01
```

The node subscribes to `/scan` (`sensor_msgs/LaserScan`), publishes the action
on `/safety/action` (`std_msgs/String`) and records every change of action
in the default chain (`~/.kyvern/chain.jsonl`, or `$KYVERN_CHAIN_PATH`),
signed with `~/.kyvern/keys/signing.key`. Verify it with:

```bash
kyvern-verify ~/.kyvern/chain.jsonl --policy examples/ros2_safety_demo/safety_policy.yaml --pubkey ~/.kyvern/keys/signing.pub
```

The controller records changes of action rather than every scan, so a 10 Hz
controller does not fill the chain with identical decisions; every stop and
every resume is in it.

## Files

| File | What it is |
|---|---|
| `safety_policy.yaml` | The robot's policy: the first rule whose limit the closest obstacle is below applies |
| `safety_controller.py` | The robot's decision logic and the `record_decision()` call; no ROS2 dependency |
| `ros2_node.py` | ROS2 wrapper: `/scan` in, `/safety/action` out |
| `run_demo.py` | The scenario without ROS2, then `kyvern-verify` and `kyvern-report` |
