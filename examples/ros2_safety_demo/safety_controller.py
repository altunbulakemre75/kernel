"""A robot's own safety controller, with Kyvern recording its decisions.

The decision logic is the robot's: the thresholds come from safety_policy.yaml.
Kyvern only records what the controller decided, why, on which reading and
under which version of that policy. Nothing here depends on ROS2; ros2_node.py
feeds it LaserScan readings and run_demo.py feeds it a simulated approach.
"""
from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from cryptography.hazmat.primitives.asymmetric import ed25519

from kyvern import record_decision


@dataclass(frozen=True)
class SafetyDecision:
    action: str
    rule_id: str
    reasoning: str
    inputs: dict[str, Any]


def min_valid_range(ranges: Iterable[float], range_min: float, range_max: float) -> float | None:
    """The closest reading the sensor reports as valid (LaserScan semantics), or None."""
    valid = [r for r in ranges if not math.isnan(r) and range_min <= r <= range_max]
    return min(valid) if valid else None


class SafetyController:
    """Decides stop / slow / continue from the closest obstacle, following the
    policy's rules in order, and records each change of action.

    Recording changes rather than every scan keeps a 10 Hz controller from
    filling the chain with identical decisions; every transition (and so every
    stop and every resume) is in the chain.
    """

    def __init__(
        self,
        policy_path: str | Path,
        *,
        chain_path: str | Path | None = None,
        signing_key: ed25519.Ed25519PrivateKey | None = None,
        source: str = "safety_controller",
    ) -> None:
        self.policy_path = Path(policy_path)
        self.rules = yaml.safe_load(self.policy_path.read_text(encoding="utf-8"))["rules"]
        self.chain_path = chain_path
        self.signing_key = signing_key
        self.source = source
        self._last_action: str | None = None

    def decide(self, min_range_m: float) -> SafetyDecision:
        for rule in self.rules:
            limit = rule.get("below_m")
            if limit is None or min_range_m < limit:
                reasoning = (
                    f"closest obstacle at {min_range_m} m, below {limit} m" if limit is not None
                    else f"closest obstacle at {min_range_m} m, path clear"
                )
                return SafetyDecision(rule["action"], rule["id"], reasoning, {"min_range_m": min_range_m})
        raise ValueError(f"{self.policy_path} has no rule for a range of {min_range_m} m")

    def on_scan(self, min_range_m: float, subject_id: str | None = None) -> SafetyDecision:
        decision = self.decide(min_range_m)
        if decision.action != self._last_action:
            record_decision(
                decision.action,
                source=self.source,
                reasoning=decision.reasoning,
                inputs=decision.inputs,
                rule_id=decision.rule_id,
                subject_id=subject_id,
                policy_path=self.policy_path,
                chain_path=self.chain_path,
                signing_key=self.signing_key,
            )
            self._last_action = decision.action
        return decision
