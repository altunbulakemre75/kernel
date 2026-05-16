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

## Architecture

See [`docs/architecture.md`](docs/architecture.md) for the full design:
components, data flow, audit chain implementation (Ed25519 + SHA-256
hash chain), the guardrail downgrade-only invariant, and integration
points.

## Roadmap

- [ ] ROS2 action sink adapter
- [ ] MCP server interface
- [ ] IMM filter as default in TrackManager
- [ ] OpenAI provider in LLM chain
- [ ] Internationalization of in-code documentation (Turkish → English)

## License

Apache 2.0.

## Contact

Discussion on [Open Robotics Discourse](https://discourse.openrobotics.org/t/the-accountability-gap-in-ros2-where-does-why-did-the-robot-do-that-get-answered/54841)
or open a GitHub issue.
