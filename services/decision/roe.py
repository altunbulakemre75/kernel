"""Decision policy loader and evaluator.

Policy file is in YAML format; each rule maps a ThreatLevel + zone
condition to an Action. First matching rule wins. If none match,
the default is LOG.
"""
from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import TypeAdapter

from services.decision.schemas import Action, ROERule, ThreatLevel


_rule_list_adapter = TypeAdapter(list[ROERule])


def load_roe(path: str | Path) -> list[ROERule]:
    """Load decision policy rules from a YAML file."""
    text = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    raw = data.get("rules") if isinstance(data, dict) else data
    return _rule_list_adapter.validate_python(raw)


def evaluate_roe(
    rules: list[ROERule],
    threat_level: ThreatLevel,
    inside_zone: bool,
) -> tuple[Action, ROERule | None]:
    """Apply the first matching enabled policy rule. If none match, LOG.

    Returns:
        (action, matched_rule) — matched_rule is None if the default LOG is used
    """
    for rule in rules:
        if not rule.enabled:
            continue
        if rule.when_threat_level != threat_level:
            continue
        if rule.when_inside_zone is not None and rule.when_inside_zone != inside_zone:
            continue
        return rule.action, rule
    return Action.LOG, None
