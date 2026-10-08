# Kyvern

[![Build](https://img.shields.io/github/actions/workflow/status/altunbulakemre75/kyvern/ci.yml?branch=main&label=build)](https://github.com/altunbulakemre75/kyvern/actions) [![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE) [![Python](https://img.shields.io/badge/python-3.10%2B-blue)](#quick-start) [![Status](https://img.shields.io/badge/status-alpha-orange)](#status) [![EU AI Act](https://img.shields.io/badge/EU%20AI%20Act-Article%2012%20%7C%2014-blue)](#eu-ai-act-compliance-reports)

Decision provenance and accountability infrastructure for autonomous systems.

When an autonomous system makes a consequential decision — a robot stops
mid-motion, a vehicle reroutes, an actuator fires — *what* happened is
usually loggable. *Why* it happened, in a form a safety officer, regulator,
or court can read, is almost always reconstructed after the fact, by hand.

Kyvern is the missing layer:

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

v0.3.0 (2026-10-07) made the audit path production-grade: every decision
from the live pipeline is recorded in the verifiable chain or not returned
at all, several processes can append safely, every entry names its signing
key, and the chain head can be anchored with external RFC 3161 timestamps.
See [`CHANGELOG.md`](CHANGELOG.md).

## Quick start

Kyvern is not on PyPI yet; install from a clone of this repository.

```bash
pip install .                 # core: decisions, audit chain, kyvern-verify/report/anchor
pip install ".[mcp]"          # + kyvern-mcp (Claude Desktop)
pip install ".[llm]"          # + LLM advisor (LangGraph, Anthropic)
pip install -r requirements.txt && pytest   # full development environment
```

## Verifying decisions

For auditors and compliance officers, the decision provenance chain can be
verified offline without writing code:

```bash
kyvern-verify chain.jsonl --policy config/policies/default.yaml --pubkey ~/.kyvern/keys/signing.pub
```

Repeat `--pubkey` to verify a chain signed by more than one key (for example
after a key rotation); every entry records which key signed it. Repeat
`--policy` for a chain that spans a policy update: every Decision must be
bound to one of the given policies. Decisions recorded without a policy
(`run_graph()` / `decide_full()` called without `policy_path=`) cannot be
checked against one, so `kyvern-verify` lists them and fails. RuntimeEvents
are counted separately and are not checked against a policy.

### Anchoring the chain

Run `kyvern-anchor` on a schedule to timestamp the chain head with an
external RFC 3161 authority (IdenTrust by default; `--tsa-url` and
`--tsa-root` to change it). `kyvern-verify` then checks the receipts and
fails if an anchored entry was rewritten, even by someone holding the
signing key.

```bash
# Linux/macOS, hourly (crontab -e)
0 * * * * kyvern-anchor /var/lib/kyvern/chain.jsonl
```

```bash
# Windows, hourly
schtasks /Create /SC HOURLY /TN "Kyvern anchor" /TR "kyvern-anchor C:\kyvern\chain.jsonl"
```

**Output:**

```text
✓ Chain integrity: VALID (3 decisions, 1 runtime events, all signed)
✓ Policy match: 5b64432b2dd0796f (default.yaml @ 2026-10-08 04:51 UTC): 3 decisions
✓ Signature verification: PASSED (Ed25519)
  Anchors: none (no chain.anchors.jsonl)

Decision summary:
  [0] 14:32:07  action=LOG     rule_id=POL-1  guardrails=[input-single-tick]
  [1] 14:32:09  action=ALERT   rule_id=POL-2  guardrails=[]
  [2] 14:32:12  event=sensor_anomaly source=imu_monitor
  [3] 14:32:15  action=ALERT   rule_id=POL-2  guardrails=[]

Audit hash: 5b64432b2dd0796f (verifiable against deployed policy)
```

## EU AI Act Compliance Reports

Generate a regulator-ready PDF with Article 12 (logging) and Article 14
(human oversight) compliance evidence from any signed decision chain:

```bash
kyvern-report chain.jsonl \
    --policy config/policies/default.yaml \
    --pubkey ~/.kyvern/keys/signing.pub \
    --output report.pdf \
    --system-id "AMR-Fleet-A" \
    --operator "Operations Team"
```

The PDF covers: chain integrity verification, action and threat-level
distribution, per-requirement attestation tables for Articles 12 and 14,
policy version timeline, and a cryptographic fingerprint of the report
content. See [`docs/compliance/eu_ai_act.md`](docs/compliance/eu_ai_act.md).

## MCP server (Claude Desktop)

Plug Kyvern into Claude Desktop in ~30 seconds and ask questions like
*"what did my autonomous system do in the last hour?"*:

Kyvern is not published on PyPI yet, so install from source:

```bash
git clone https://github.com/altunbulakemre75/kyvern.git
cd kyvern
pip install -e ".[mcp]"
```

Then add to your Claude Desktop config:

```json
{
  "mcpServers": {
    "kyvern": {
      "command": "kyvern-mcp",
      "args": ["--chain-file", "/path/to/chain.jsonl", "--pubkey", "/path/to/signing.pub"]
    }
  }
}
```

Five read-only tools (`query_events`, `get_event`, `get_stats`,
`verify_chain`, `search_events`) and four resources cover signed audit
query, chain verification, and active-policy metadata. See
[`docs/integrations/mcp.md`](docs/integrations/mcp.md).

## Recording events from your existing stack

You do not have to adopt Kyvern's decision engine to get a signed record.
`RuntimeEvent` lets sensor monitors, guard middleware, or other upstream
components append their own evidence to the same signed chain as Kyvern
Decisions:

```python
from shared.paths import default_chain_path
from shared.schemas import RuntimeEvent
from services.decision.audit_chain import append_runtime_event, load_or_create_keypair

chain_path = default_chain_path()       # the chain run_graph() writes
signing_key = load_or_create_keypair()  # ~/.kyvern/keys/signing.key

event = RuntimeEvent(
    event_type="guardrail_downgrade",
    source="kinematic_guard",
    source_id="kg-main",
    timestamp_iso="2026-05-20T12:00:00+00:00",
    payload={"reason": "speed_exceeded"},
)
append_runtime_event(event, chain_path, signing_key)
```

`append_runtime_event()` also takes an optional `policy_version_id` to record
which policy was in force; auditor tools show it but only check Decisions
against a policy.

Decisions from `run_graph()` are appended to the same chain automatically
(`~/.kyvern/chain.jsonl` by default; override with `chain_path=` or
`KYVERN_CHAIN_PATH`). If a decision cannot be recorded, `run_graph()` raises
`AuditWriteError` instead of returning it.

See [`docs/architecture.md` §8](docs/architecture.md) for chain semantics.

## Integrations

**ROS2 bridge:** publishes signed Decision objects to a ROS2 topic for
consumption by autonomous systems. See [`docs/integrations/ros2.md`](docs/integrations/ros2.md).

## Architecture

See [`docs/architecture.md`](docs/architecture.md) for the full design:
components, data flow, audit chain implementation (Ed25519 + SHA-256
hash chain), the guardrail downgrade-only invariant, and integration
points.

## Security

Kyvern defends against two primary threats: insider post-hoc tampering of
decision history (Ed25519 + SHA-256 hash chain) and AI-induced unsafe
escalation (LLM advisory ceiling + guardrail downgrade-only invariant).

It does not defend against signing key compromise, sensor-level deception,
runtime intrusion, or network attacks — those are operator responsibilities.

See [`docs/threat-model.md`](docs/threat-model.md) for the full threat model,
including explicit non-defenses and what this means for compliance claims.

## Roadmap

- [x] EU AI Act Article 12 &amp; 14 compliance report generator (`cli/kyvern_report.py`)
- [x] ROS2 publisher (`services/integrations/ros2_bridge.py`)
- [ ] ROS2 action sink with feedback loop (planned)
- [x] MCP server interface (`kyvern/mcp/`, `kyvern-mcp`)
- [x] Upstream evidence events in the audit chain (`RuntimeEvent`)
- [x] v0.3.0: fail-closed audit path, verbatim chain storage, key IDs,
      external chain-head anchoring (RFC 3161)
- [ ] IMM filter as default in TrackManager
- [ ] OpenAI provider in LLM chain
- [ ] Internationalization of in-code documentation (Turkish → English)

## License

Apache 2.0.

## Contact

Discussion on [Open Robotics Discourse](https://discourse.openrobotics.org/t/the-accountability-gap-in-ros2-where-does-why-did-the-robot-do-that-get-answered/54841)
or open a GitHub issue.
