# kernel

Decision provenance and accountability infrastructure for autonomous systems.

When an autonomous system makes a consequential decision — a robot stops
mid-motion, a vehicle reroutes, an actuator fires — *what* happened is
usually loggable. *Why* it happened, in a form a safety officer, regulator,
or court can read, is almost always reconstructed after the fact, by hand.

`kernel` is the missing layer:

- **Rule-first decision engine.** Every action traces back to a
  human-authored policy. AI advises; rules decide.
- **Cryptographically signed audit chain.** Every decision is recorded
  with full provenance: which rule fired, which inputs triggered it,
  which guardrails ran, what was downgraded. Linked via Ed25519 signature.
- **Guardrail-downgrade-only pattern.** Safety layers can only make
  decisions safer, never more dangerous. Mathematically enforced.
- **LLM advisor with prompt injection defense.** Models suggest; they
  do not act. Adversarial inputs are sanitized before reaching the
  decision boundary.
- **Air-gap deployable.** Runs fully offline with local model fallback.
  No data leaves the deployment environment.

## Status

Pre-1.0. Core engine and audit chain are battle-tested in a private
deployment (separate codebase). This repository is the generalized,
domain-neutral open-core extraction.

Active areas: ROS2 adapter, MCP server interface, EU AI Act Article 12
compliance reporting.

## Quick start

```bash
pip install -r requirements.txt
pytest
```

## Verifying decisions

For auditors and compliance officers, the decision provenance chain can be
verified offline without writing code:

```bash
kernel-verify chain.jsonl --policy config/policies/default.yaml --pubkey ~/.kernel/keys/signing.pub
```

**Output:**

```text
✓ Chain integrity: VALID (5 decisions, all signed)
✓ Policy match: c1fc5724f6b02970 (default.yaml @ 2026-05-15 18:30 UTC)
✓ Signature verification: PASSED (Ed25519)

Decision summary:
  [0] 14:32:07  action=LOG      rule_id=r_001  guardrails=[]
  [1] 14:32:09  action=ALERT    rule_id=r_003  guardrails=[geofence]
  [2] 14:32:15  action=HANDOFF  rule_id=r_001  guardrails=[]

Audit hash: c1fc5724f6b02970 (verifiable against deployed policy)
```

## EU AI Act Compliance Reports

Generate a regulator-ready PDF with Article 12 (logging) and Article 14
(human oversight) compliance evidence from any signed decision chain:

```bash
kernel-report chain.jsonl \
    --policy config/policies/default.yaml \
    --pubkey ~/.kernel/keys/signing.pub \
    --output report.pdf \
    --system-id "AMR-Fleet-A" \
    --operator "Operations Team"
```

The PDF covers: chain integrity verification, action and threat-level
distribution, per-requirement attestation tables for Articles 12 and 14,
policy version timeline, and a cryptographic fingerprint of the report
content. See [`docs/compliance/eu_ai_act.md`](docs/compliance/eu_ai_act.md).

## Integrations

**ROS2 bridge:** publishes signed Decision objects to a ROS2 topic for
consumption by autonomous systems. See [`docs/integrations/ros2.md`](docs/integrations/ros2.md).

## Architecture

See [`docs/architecture.md`](docs/architecture.md) for the full design:
components, data flow, audit chain implementation (Ed25519 + SHA-256
hash chain), the guardrail downgrade-only invariant, and integration
points.

## Roadmap

- [x] EU AI Act Article 12 &amp; 14 compliance report generator (`cli/kernel_report.py`)
- [x] ROS2 publisher (`services/integrations/ros2_bridge.py`)
- [ ] ROS2 action sink with feedback loop (planned)
- [ ] MCP server interface
- [ ] IMM filter as default in TrackManager
- [ ] OpenAI provider in LLM chain
- [ ] Internationalization of in-code documentation (Turkish → English)

## License

Apache 2.0.

## Contact

Discussion on [Open Robotics Discourse](https://discourse.openrobotics.org/t/the-accountability-gap-in-ros2-where-does-why-did-the-robot-do-that-get-answered/54841)
or open a GitHub issue.
