# Kyvern — Architecture

> Last updated: 2026-10-08 · Status: pre-1.0

---

## 1. Overview

Kyvern is a decision-provenance layer that sits between autonomous/AI
systems (sensors, perception, planners) and downstream actuators (robots,
vehicles, effectors). It does not replace the autonomy stack — it wraps
the decision boundary so that every consequential action is traceable to a
human-authored policy rule, every guardrail evaluation is recorded, and the
full chain is cryptographically replayable. The core guarantee: an
external auditor can take any historical decision, feed in the same
inputs, and reproduce the exact same output — including which rules fired,
which LLM advice was considered and overridden, and which guardrails
downgraded the action.

---

## 2. Core Components

### 2.1 `services/decision/` — Rule Engine + LLM Advisor + Guardrails

The decision layer is the heart of the system. It has three sub-layers
that execute in a fixed order:

| Sub-layer | Key files | Role |
|-----------|-----------|------|
| **Rule engine** | `rules.py` (`assess_threat`), `roe.py` (`evaluate_roe`) | Deterministic, weighted-score assessment. Factors: zone proximity, transponder presence, speed, heading, confidence. Thresholds map to `ThreatLevel` enum (LOW/MEDIUM/HIGH/CRITICAL). Policy rules are loaded from YAML (`config/policies/default.yaml`) via the `ROERule` Pydantic model. First matching enabled rule wins. |
| **LLM advisor** | `llm_client.py` (`query_llm`), `llm_graph.py` (`_reconcile_action`) | Optional. Queries an LLM for an independent assessment. Provider fallback chain: Anthropic Claude → Ollama (local) → None. The advisor **cannot** recommend ENGAGE — only LOG, ALERT, or HANDOFF. Prompt injection defense is handled by `sanitize.py` (`sanitize_track_for_llm`), which applies allowlist filtering, control-char stripping, and injection-pattern detection before any track data reaches the LLM prompt. |
| **Guardrails** | `guardrails.py` (`apply_guardrails`) | Post-decision safety filters. Three implemented guardrails: `input_track_guardrail` (rejects low-confidence or single-tick tracks), `friendly_zone_guardrail` (blocks action inside protected areas), `civilian_pattern_guardrail` (detects civil transponder codes and airliner flight profiles). Guardrails can only **downgrade** — see §6. |

The full pipeline is orchestrated by a 5-node state machine in
`llm_graph.py` (`run_graph`): classify → retrieve_roe → reason →
guardrail → finalize. `retrieve_roe` is a hook for a policy-retrieval
(RAG) module that this repository does not ship; without one it passes
the state through. When LangGraph is installed, it runs as a
`StateGraph`; otherwise, it falls back to plain sequential `await` calls.
Both paths produce the same `Decision` output.

Entry points:
- `threat_graph.decide()` — sync, rule-only fast path (no LLM).
- `threat_graph.decide_full()` — sync wrapper over `run_graph` (full pipeline).
- `llm_graph.run_graph()` — async, production entry point.

### 2.2 What is not in this repository

The original deployment also had sensor adapters (camera, RF/OpenDroneID,
Wi-Fi), multi-sensor tracking (Kalman/IMM fusion over NATS) and counter-UAS
autonomy (intercept planning, MAVSDK). That code now lives in a separate
private repository. Kyvern does not need it: it records decisions from
whatever perception and planning stack produces them — its own example
engine (§2.1) or yours, through `RuntimeEvent` (§8).

### 2.3 `shared/`

| Module | Purpose |
|--------|---------|
| `paths.py` | Per-user locations: `~/.kyvern`, the default chain path (`KYVERN_CHAIN_PATH`), the pre-rename `~/.kernel` guard. |
| `schemas.py` | `RuntimeEvent`, the record type for upstream evidence (§8). |

---

## 3. Data Flow

The system processes data through a linear pipeline:

1. **Input** — A track or situation report from your perception stack: a
   dict with an identifier, position, velocity, confidence and source
   information. Kyvern does not do perception or tracking itself.

2. **Decision engine** — Each track is evaluated by the
   rule engine (`assess_threat` → `evaluate_roe`). If the LLM advisor
   is enabled (`KYVERN_DECISION_LLM_ENABLED=true`), the track is
   independently assessed by the LLM via `query_llm`. The rule engine
   and LLM outputs are reconciled: the LLM can escalate (LOG → ALERT
   → HANDOFF) but **never** to ENGAGE, and it cannot downgrade.

3. **Guardrails** — `apply_guardrails` runs all registered guardrail
   functions against the pre-decision. Any triggered guardrail can only
   **downgrade** the action severity (see §6). Guardrail IDs and
   reasoning are appended to the `Decision` object without truncation.

4. **Audit chain** — The finalized `Decision` (including raw LLM
   response, guardrail trace, rule reference, and full reasoning) is
   signed and appended to the JSONL audit chain by `ChainWriter`
   (`services/decision/chain_writer.py`): under an inter-process file
   lock it reads the last entry, links and signs the new one, writes it
   and fsyncs. The chain file is `run_graph(chain_path=...)`, else
   `$KYVERN_CHAIN_PATH`, else `~/.kyvern/chain.jsonl` — the same file
   `kyvern-verify`, `kyvern-report` and `kyvern-mcp` read. If the
   decision cannot be recorded, `run_graph()` raises `AuditWriteError`
   and returns nothing.

5. **Action** — The `Decision` is published for downstream consumption.
   For ENGAGE actions, `requires_operator_approval` is hardcoded to
   `true` regardless of policy configuration. See §7 for action sinks.

---

## 4. Audit Chain Design

Every `Decision` object carries full provenance: the originating track
state, the rule that fired (`roe_reference`), the raw LLM response
(unsanitized, stored in `llm_raw_response`), the provider and model used,
which guardrails triggered (`guardrails_triggered` list), and the
guardrail reasoning (untruncated in `guardrail_reasoning`, separate from
the main `reasoning` field which is capped at 500 chars).

The planned cryptographic signing pattern works as follows: each
`Decision` is serialized to a canonical JSON form, hashed (SHA-256), and
the hash is signed with a deployment-specific Ed25519 key. The previous
decision's hash is included in the current record, forming a hash chain.
This means any tampering with a historical record breaks the chain from
that point forward. A verifier can replay the entire decision sequence:
feed the same track inputs through the same rule set and guardrails, and
confirm that the outputs match the signed records.

**Current status:** Every entry carries `signature`, `prev_hash`,
`payload_hash`, `chain_index` and `key_id` (the first 16 hex chars of
SHA-256 over the raw public key, covered by the signature). Decisions
from `run_graph()` and RuntimeEvents from `append_runtime_event()` are
both appended through `ChainWriter`, so they share one chain and one
`chain_index` sequence. Several processes on one host can append
safely; several hosts writing one chain is not supported.

Code example:
```python
from services.decision.audit_chain import Keyring, describe_chain_failure, verify_chain

keys = Keyring.from_pem_files(["signing.pub", "signing-<old key id>.pub"])
is_valid, broken_idx = verify_chain(decisions, keys)
if not is_valid:
    print(f"Chain broken at index {broken_idx}: "
          f"{describe_chain_failure(decisions, broken_idx, keys)}")
```

**Anchoring.** `kyvern-anchor` (`cli/kyvern_anchor.py`) timestamps the chain
head with an external authority. The statement it anchors is the canonical
JSON `{"chain_index": n, "kyvern_anchor": 1, "payload_hash": h}`; the receipt
goes to `<chain stem>.anchors.jsonl`. `services/decision/anchors.py` defines
the `Anchor` protocol (`name`, `request(statement)`, `verify(statement,
receipt)`); `services/decision/rfc3161_anchor.py` is the RFC 3161
implementation. Another kind of anchor implements the same two methods under
a new `name` and is added to the mapping `kyvern-verify` passes to
`check_anchors()`.

The same chain also carries signed evidence events from external
systems (`RuntimeEvent`) — see §8.

---

## 5. Policy Versioning

Every Decision is cryptographically tied to a specific policy version. 
When the rules are evaluated, a canonical, deterministic SHA-256 hash 
(`version_id`) of the `default.yaml` policy is computed. This hash 
is attached to the Decision prior to signing. 

If someone edits the YAML between two decisions, the hash changes, 
creating an immutable record of the divergence. An external auditor 
can verify a historical decision against the policy file claimed by 
its `policy_version_id`:

```python
from services.decision.audit_chain import verify_decision_against_policy

is_valid, reason = verify_decision_against_policy(decision, "config/policies/default.yaml", public_key)
if not is_valid:
    print(f"Verification failed: {reason}")
```

---

## 6. Guardrail Downgrade-Only Invariant

Guardrails enforce a one-way safety property: they can only reduce the
severity of a decision, never increase it. This is the
**downgrade-only invariant**.

The `Action` enum has a strict severity ordering maintained in
`guardrails.py`:

```
LOG (0) < ALERT (1) < HANDOFF (2) < ENGAGE (3)
```

When a guardrail triggers, it proposes a `downgrade_to` action. The
orchestrator (`apply_guardrails`) only applies the downgrade if
`_SEVERITY[proposed] < _SEVERITY[current_action]`. A guardrail that
returns `downgrade_to=ENGAGE` when the current action is `ALERT` is
silently ignored — the comparison fails and the action stays at `ALERT`.

This means a false-positive guardrail trigger produces a safer (more
conservative) outcome, never a dangerous one. The worst case of a
guardrail bug is an unnecessary downgrade to LOG, which results in
logging-only — the safest possible state. The system cannot be tricked
into escalation through guardrail manipulation.

The same principle applies to the LLM advisor reconciliation (in
`llm_graph.py`, `_reconcile_action`): the LLM can **escalate** (propose
a higher severity than the rule engine), but guardrails run **after**
reconciliation and can only bring it back down.

---

## 7. Integration Points

### LLM Backends (implemented)
- **Ollama** — Default for air-gapped deployments. Connects to
  `localhost:11434`, model configurable via `OLLAMA_MODEL` env
  (default: `llama3.1:8b`). Structured output via `format=json`.
- **Anthropic Claude** — Used when `ANTHROPIC_API_KEY` is set. Structured
  output via tool-use (`submit_assessment`). Provider chain:
  Anthropic → Ollama → None (graceful degradation).
- **OpenAI** — Not yet implemented. `llm_client.py` is structured for
  adding a `_try_openai` step in the provider chain.

### Action Sinks
- **ROS2** — `services/integrations/ros2_bridge.py` publishes signed
  Decisions as JSON on a ROS2 topic (`std_msgs/String`);
  `ros2_subscriber_example.py` verifies them on the receiving side.
- **Custom** — The `Decision` Pydantic model serializes to JSON. Any
  system that can consume JSON over NATS, HTTP, or direct import can act
  as a sink today.

### Audit Query Interface (implemented)
- **MCP (Model Context Protocol)** — `kyvern-mcp` (`kyvern/mcp/`) is a
  read-only stdio MCP server that lets MCP-compatible AI agents query the
  JSONL audit chain: 5 tools (`query_events`, `get_event`, `get_stats`,
  `verify_chain`, `search_events`) and 4 `kyvern://` resources. It covers
  both Decisions and upstream RuntimeEvents — see §8.

---

## 8. Upstream Evidence Events

`RuntimeEvent` is a typed record for signing evidence events from
**external systems** (sensor monitors, guard middleware, external policy
adapters) into the audit chain. How it differs from a `Decision`:

- A **Decision** comes out of Kyvern's own decision graph ("I did
  this") — controlled.
- A **RuntimeEvent** comes from an external source ("I observed
  this") — uncontrolled.

Both are written to the same JSONL audit chain file with **the same
Ed25519 signature scheme, the same SHA-256 hash link, and the same
`chain_index` counter**. RuntimeEvent records carry a
`record_type: "runtime_event"` discriminator field; Decisions do not
have this field (backward compatibility — a record without
`record_type` is read as a Decision).

**Use cases:**
- Sensor anomaly reports (e.g. `event_type="sensor_anomaly"`,
  `source="lidar_monitor"`)
- Downgrades by external guard middleware
  (`event_type="guardrail_downgrade"`, `source="kinematic_guard"`)
- Violation reports from policy adapters
  (`event_type="policy_violation"`)

**Mixed-chain verification:** `verify_chain()` is type-agnostic; it
verifies a chain of interleaved RuntimeEvents and Decisions in a single
linear scan. `chain_index` forms **one monotonic sequence** across both
record types — there are no separate counters.

**Asymmetric protection:** Because a RuntimeEvent comes from an external
system, its `payload` is capped at 64 KB (`PayloadTooLargeError`).
Decisions have no such limit, since they are produced by Kyvern's own
controlled policy engine.

**API:**
```python
from shared.schemas import RuntimeEvent
from services.decision.audit_chain import append_runtime_event

event = RuntimeEvent(
    event_type="sensor_anomaly",
    source="lidar_monitor",
    source_id="lidar-front-01",
    timestamp_iso="2026-05-20T12:00:00+00:00",
    payload={"distance_m": 4.2, "object_class": "vehicle"},
)
signed = append_runtime_event(event, chain_path, signing_key)  # policy_version_id= is optional
```

The MCP `query_events` tool filters RuntimeEvents via its `event_type`
and `source` parameters; its `action` and `threat_level` parameters
filter Decisions.

---

## Appendix: Directory Map

```
kyvern/
├── cli/
│   ├── kyvern_anchor.py          # kyvern-anchor: RFC 3161 receipts for the chain head
│   ├── kyvern_report.py          # kyvern-report: EU AI Act evidence PDF
│   └── kyvern_verify.py          # kyvern-verify: offline chain, policy and anchor check
├── config/
│   └── policies/
│       └── default.yaml          # Decision policy rules (YAML)
├── kyvern/
│   ├── audit/store.py            # AuditChainStore: read, filter and verify the JSONL chain
│   ├── mcp/                      # kyvern-mcp: read-only MCP server (tools, resources)
│   └── sandwich/                 # Dual-LLM (privileged/quarantined) isolation
├── services/
│   ├── decision/
│   │   ├── anchors.py            # Anchor protocol, receipts, check_anchors
│   │   ├── audit_chain.py        # Sign/verify entries, keyring, policy binding, RuntimeEvent append
│   │   ├── chain_writer.py       # ChainWriter: locked, fsynced appends
│   │   ├── guardrails.py         # apply_guardrails, GuardrailResult, haversine_m
│   │   ├── llm_client.py         # LLMResponse, query_llm, provider chain
│   │   ├── llm_graph.py          # 5-node GraphState pipeline, run_graph
│   │   ├── policy_loader.py      # load_policy, SHA-256 policy version id
│   │   ├── rfc3161_anchor.py     # RFC 3161 timestamp authority client
│   │   ├── roe.py                # load_roe, evaluate_roe
│   │   ├── rules.py              # assess_threat, ThreatAssessment
│   │   ├── sanitize.py           # sanitize_track_for_llm, UnsafeContent
│   │   ├── schemas.py            # Decision, Action, ThreatLevel, ROERule
│   │   └── threat_graph.py       # decide (sync), decide_full (sync wrapper)
│   └── integrations/
│       ├── ros2_bridge.py        # Publish signed Decisions on a ROS2 topic
│       └── ros2_subscriber_example.py  # Verify them on the receiving side
├── shared/
│   ├── paths.py                  # ~/.kyvern, default chain path, ~/.kernel guard
│   └── schemas.py                # RuntimeEvent
├── scripts/                      # Demo chain generator, core-install smoke test
└── tests/                        # audit, cli, decision, integrations, mcp, sandwich
```
