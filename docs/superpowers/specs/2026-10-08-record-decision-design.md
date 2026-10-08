# Recording your own decisions: `kyvern.record_decision()`

**Status:** approved by the maintainer (2026-10-08, "approve all"); design
choices below were made without a separate review and are listed in §6.
**Context:** positioning of 2026-10-07: Kyvern is an audit layer for the
decisions a team's *own* system makes (a robot's safety controller, a planner,
an operator). Today a team can only record RuntimeEvents (not policy-checked)
or run Kyvern's example threat engine.

## 1. API

```python
from kyvern import record_decision

record_decision(
    "stop",                                  # the action the system took
    source="safety_controller",              # who decided ("operator" for a person)
    reasoning="obstacle at 0.4 m < 0.5 m",
    inputs={"obstacle_distance_m": 0.4},     # what the decision was based on (<= 64 KB)
    rule_id="stop-on-obstacle",              # the rule in your policy that fired
    policy_path="safety_policy.yaml",        # binds the decision to that policy version
)
```

Optional: `subject_id`, `requires_operator_approval` (default False),
`timestamp_iso` (default now, UTC; must carry an offset), `chain_path`
(default: the chain `run_graph()` writes), `signing_key` (default: the
`~/.kyvern` key). Returns the signed `RecordedDecision`; raises
`AuditWriteError` if it cannot be recorded, a `ValidationError` for bad input.

## 2. Record

`RecordedDecision` (in `shared/schemas.py`, next to `RuntimeEvent`):
`record_type: "decision"`, `action`, `source`, `reasoning`, `inputs`, `rule_id`,
`subject_id`, `requires_operator_approval`, `timestamp_iso`,
`policy_version_id`, `policy_path`, plus the chain fields. Neutral field names:
no `threat_level`, `roe_reference` or `track_id`.

A policy is any YAML file with a `rules:` list (the shape of each rule is the
team's own); its version id is the SHA-256 that `load_policy()` already
computes, so `kyvern-verify --policy` works unchanged.

## 3. Auditor tools

The tools already treat every record that is not a RuntimeEvent as a decision,
so recorded decisions are counted as decisions and policy-checked. Changes:

- `kyvern-verify` summary: `action=STOP rule_id=stop-on-obstacle source=safety_controller`.
- `kyvern-report`: the threat-level table covers only decisions that have a
  threat level (recorded decisions do not); the Article 12(2)(a) check asks a
  recorded decision for `inputs` and `reasoning` (an engine decision still for
  `threat_level`, `roe_reference`, `guardrails_triggered`); 12(2)(c) asks it for
  `action`, `timestamp_iso`, `requires_operator_approval` and `source`.
- MCP: unchanged (`record_type` "decision" is what it already assumes).

## 4. Tests

Recording (fields, signature, chain order, mixed with `run_graph()` decisions
and RuntimeEvents, default chain), validation (64 KB inputs cap, timestamp
without offset, empty action), policy binding through `kyvern-verify`
(bound passes, unbound fails), `kyvern-report` on recorded decisions (checks
pass, no "unknown" threat bucket), the MCP store reading them.

## 5. Docs

README leads its quick start with recording your own decisions;
`docs/architecture.md` §8 describes `RecordedDecision` next to `RuntimeEvent`.

## 6. Choices made without review

- `record_type` is `"decision"`; Kyvern's own engine decisions keep having no
  `record_type` (unchanged chain format).
- Public import path `kyvern.record_decision`, its future home after the
  v0.4.0 namespace move; implemented next to `append_runtime_event()`.
- `source` is free text; `"operator"` is counted as a human intervention by the
  report, as for engine decisions.
- An unbound recorded decision fails `kyvern-verify --policy`, the same rule as
  for engine decisions (0.3.2).
