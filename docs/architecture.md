# kernel — Architecture

> Last updated: 2026-05-14 · Status: pre-1.0

---

## 1. Overview

kernel is a decision-provenance layer that sits between autonomous/AI
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
| **LLM advisor** | `llm_client.py` (`query_llm`), `llm_advisor.py`, `llm_graph.py` | Optional. Queries an LLM for an independent assessment. Provider fallback chain: Anthropic Claude → Ollama (local) → None. The advisor **cannot** recommend ENGAGE — only LOG, ALERT, or HANDOFF. Prompt injection defense is handled by `sanitize.py` (`sanitize_track_for_llm`), which applies allowlist filtering, control-char stripping, and injection-pattern detection before any track data reaches the LLM prompt. |
| **Guardrails** | `guardrails.py` (`apply_guardrails`) | Post-decision safety filters. Three implemented guardrails: `input_track_guardrail` (rejects low-confidence or single-tick tracks), `friendly_zone_guardrail` (blocks action inside protected areas), `civilian_pattern_guardrail` (detects civil transponder codes and airliner flight profiles). Guardrails can only **downgrade** — see §5. |

The full pipeline is orchestrated by a 5-node state machine in
`llm_graph.py` (`run_graph`): classify → retrieve_roe → reason →
guardrail → finalize. When LangGraph is installed, it runs as a
`StateGraph`; otherwise, it falls back to plain sequential `await` calls.
Both paths produce the same `Decision` output.

Entry points:
- `threat_graph.decide()` — sync, rule-only fast path (no LLM).
- `threat_graph.decide_full()` — sync wrapper over `run_graph` (full pipeline).
- `llm_graph.run_graph()` — async, production entry point.

### 2.2 `services/fusion/` — Multi-Sensor State Estimation

Fuses measurements from heterogeneous sensors into unified tracks.

| Module | Role |
|--------|------|
| `fusion_service.py` (`FusionService`) | NATS subscriber orchestrator. Listens on `nizam.raw.rf.odid.>`, `nizam.raw.camera.>`, and `nizam.raw.sim.cop` subjects. Includes `SlidingWindowLimiter` and `QueueCircuitBreaker` for DoS protection. Runs a fixed-rate tick loop (default 100 ms). |
| `track_manager.py` (`TrackManager`) | Track lifecycle: tentative → confirmed → lost → deleted. Each tick: predict → associate → update → spawn → reap. Lifecycle thresholds: N_CONFIRM=3, M_LOST=3, K_DELETE=10. |
| `kf_engine.py` | 3D constant-velocity Kalman filter (filterpy). State: `[x, y, z, vx, vy, vz]`. Measurement: `[x, y, z]` in ENU metres. DWNA process noise model. |
| `imm_engine.py` | IMM (Interacting Multiple Model) filter. Two parallel CV filters with different process noise levels (cruise vs. maneuver). Uses filterpy's `IMMEstimator`. **Implemented but not yet wired into `TrackManager` as default.** |
| `association.py` | Hungarian algorithm + Mahalanobis gating (χ² 99.7% gate at 3.77). Uses `scipy.optimize.linear_sum_assignment`. |

Coordinate system: all internal state is in ENU (East-North-Up) metres
relative to a configurable reference point. `shared/geo.py` handles
lat/lon ↔ ENU conversion (pyproj when available, flat-Earth fallback
otherwise).

### 2.3 `services/schemas/` — Shared Data Contracts

All inter-service data is defined as Pydantic v2 models:

- `track.py` — `Measurement`, `Track`, `TrackState`, `SensorType`
- `detection.py` — `CameraDetectionEvent`, `Detection`, `BoundingBox`
- `rf.py` — `ODIDEvent`, `ODIDBasicID`, `ODIDLocation` (ASTM F3411),
  `WiFiOUIEvent`
- `services/decision/schemas.py` — `ThreatAssessment`, `Decision`,
  `Action`, `ThreatLevel`, `DecisionSource`, `ROERule`

These schemas serve as the contract between fusion, decision, and any
future downstream consumers. All enum fields are `str, Enum` for JSON
serialization. `Decision` includes audit-specific fields
(`llm_raw_response`, `guardrails_triggered`, `guardrail_reasoning`) that
are never truncated.

### 2.4 `shared/` — Common Utilities

| Module | Purpose |
|--------|---------|
| `clock.py` | Deterministic `Clock` / `FakeClock` protocol for testable time. Process-global `get_clock()` / `set_clock()` accessor pair. Also provides `Rng` protocol for seeded randomness. |
| `geo.py` | Lat/lon ↔ ENU coordinate conversion. pyproj (accurate) or flat-Earth (fallback). |
| `lifecycle.py` | `run_with_shutdown()` — SIGTERM/SIGINT graceful shutdown for async services. |
| `heartbeat.py` | Lightweight orchestrator heartbeat client. Background daemon thread, zero external dependencies. |
| `rate_limit.py` | `SlidingWindowLimiter` and `QueueCircuitBreaker` for sensor-level DoS protection. |
| `logging_setup.py` | Structured logging configuration. |
| `auth.py` | Authentication utilities. |

### 2.5 Other Service Directories

- `services/autonomy/` — Geofence enforcement (`geofence.py`,
  `NoFlyZone`, `violates_geofence`), intercept planning
  (`intercept_planner.py`), MAVSDK action sender (`mavsdk_sender.py`).
  **Intercept planner and MAVSDK sender are implemented but not
  integration-tested against real hardware.**
- `services/detectors/` — Sensor adapters for camera and RF. Contains
  camera calibration / bbox-to-position projection. **Detector modules
  exist but are tightly coupled to the original deployment; generalization
  is in progress.**

---

## 3. Data Flow

The system processes data through a linear pipeline:

1. **Sensors** — External sensors (cameras, RF/ODID receivers, radar,
   AIS) publish raw detection events to NATS subjects
   (`nizam.raw.camera.*`, `nizam.raw.rf.odid.*`, etc.). Each event is a
   JSON-serialized Pydantic model (`CameraDetectionEvent`, `ODIDEvent`,
   etc.).

2. **Fusion** — `FusionService` subscribes to these subjects, converts
   raw events into `Measurement` objects (with ENU coordinates and
   per-sensor noise estimates), and feeds them to `TrackManager`.
   TrackManager runs the predict-associate-update cycle per tick,
   producing a list of `Track` objects with Kalman-filtered state
   estimates.

3. **Decision engine** — Each confirmed track is evaluated by the
   rule engine (`assess_threat` → `evaluate_roe`). If the LLM advisor
   is enabled (`KERNEL_DECISION_LLM_ENABLED=true`), the track is
   independently assessed by the LLM via `query_llm`. The rule engine
   and LLM outputs are reconciled: the LLM can escalate (LOG → ALERT
   → HANDOFF) but **never** to ENGAGE, and it cannot downgrade.

4. **Guardrails** — `apply_guardrails` runs all registered guardrail
   functions against the pre-decision. Any triggered guardrail can only
   **downgrade** the action severity (see §5). Guardrail IDs and
   reasoning are appended to the `Decision` object without truncation.

5. **Audit chain** — The finalized `Decision` (including raw LLM
   response, guardrail trace, rule reference, and full reasoning) is
   persisted. Currently: PostgreSQL via `asyncpg` in the `finalize` node
   when `KERNEL_DB_DSN` is set. **Cryptographic signing is designed but
   not yet implemented** — see §4.

6. **Action** — The `Decision` is published for downstream consumption.
   For ENGAGE actions, `requires_operator_approval` is hardcoded to
   `true` regardless of policy configuration. Action sinks are planned
   (see §6).

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

**Current status:** The `Decision` model stores all fields needed for
replay. The `finalize` node in `llm_graph.py` persists to PostgreSQL.
The hash-chain and Ed25519 signing are **designed but not yet
implemented**. The Pydantic model is structured so that adding signing
requires only a new field (`signature: str | None`) and a post-persist
hook — no schema migration needed.

---

## 5. Guardrail Downgrade-Only Invariant

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

## 6. Integration Points

### Sensor Adapters (implemented, extensible)
- **RF/ODID** — ASTM F3411 (OpenDroneID) via NATS. Schema: `ODIDEvent`.
- **Camera** — YOLO-family detectors with calibration-based
  bbox-to-position projection. Schema: `CameraDetectionEvent`.
- **Radar/AIS** — Schema defined (`SensorType.RADAR`, `SensorType.AIS`),
  adapter stubs present. No production adapter yet.
- Adding a new sensor type requires: (1) a Pydantic event schema in
  `services/schemas/`, (2) a NATS callback in `FusionService` that
  converts the event to `Measurement`, (3) an entry in `SensorType` enum.

### LLM Backends (implemented)
- **Ollama** — Default for air-gapped deployments. Connects to
  `localhost:11434`, model configurable via `OLLAMA_MODEL` env
  (default: `llama3.1:8b`). Structured output via `format=json`.
- **Anthropic Claude** — Used when `ANTHROPIC_API_KEY` is set. Structured
  output via tool-use (`submit_assessment`). Provider chain:
  Anthropic → Ollama → None (graceful degradation).
- **OpenAI** — Not yet implemented. `llm_client.py` is structured for
  adding a `_try_openai` step in the provider chain.

### Action Sinks (planned)
- **ROS2** — Planned adapter for publishing `Decision` as ROS2 messages.
  Not yet implemented.
- **MCP (Model Context Protocol)** — Planned server interface for
  exposing kernel's decision API to MCP-compatible AI agents. Not yet
  implemented.
- **Custom** — The `Decision` Pydantic model serializes to JSON. Any
  system that can consume JSON over NATS, HTTP, or direct import can act
  as a sink today.

### Observability (implemented)
- **Prometheus** — `FusionService` exports
  `nizam_fusion_measurements_total`, `nizam_fusion_active_tracks`, and
  `nizam_fusion_tick_ms` metrics. Decision layer metrics are planned.
- **Structured logging** — via `shared/logging_setup.py`.
- **Heartbeat** — `shared/heartbeat.py` provides orchestrator health
  registration.

---

## Appendix: Directory Map

```
kernel/
├── config/
│   └── policies/
│       └── default.yaml          # Decision policy rules (YAML)
├── services/
│   ├── autonomy/
│   │   ├── geofence.py           # NoFlyZone, haversine_m, violates_geofence
│   │   ├── intercept_planner.py  # Waypoint planning (implemented)
│   │   ├── mavsdk_sender.py      # MAVSDK action sender (implemented)
│   │   └── schemas.py            # Waypoint model
│   ├── decision/
│   │   ├── guardrails.py         # apply_guardrails, GuardrailResult
│   │   ├── llm_advisor.py        # query_llm_advisor, reconcile
│   │   ├── llm_client.py         # LLMResponse, query_llm, provider chain
│   │   ├── llm_graph.py          # 5-node GraphState pipeline, run_graph
│   │   ├── roe.py                # load_roe, evaluate_roe
│   │   ├── rules.py              # assess_threat, ThreatAssessment
│   │   ├── sanitize.py           # sanitize_track_for_llm, UnsafeContent
│   │   ├── schemas.py            # Decision, Action, ThreatLevel, ROERule
│   │   └── threat_graph.py       # decide (sync), decide_full (sync wrapper)
│   ├── detectors/
│   │   ├── camera/               # Camera calibration + projection
│   │   └── rf/                   # RF adapter stubs
│   ├── fusion/
│   │   ├── association.py        # Hungarian + Mahalanobis gating
│   │   ├── fusion_service.py     # FusionService (NATS orchestrator)
│   │   ├── imm_engine.py         # IMM filter (implemented, not default)
│   │   ├── kf_engine.py          # 3D constant-velocity Kalman filter
│   │   ├── model_matcher.py      # Entity model matching
│   │   └── track_manager.py      # TrackManager lifecycle
│   └── schemas/
│       ├── detection.py          # CameraDetectionEvent, BoundingBox
│       ├── rf.py                 # ODIDEvent, WiFiOUIEvent (ASTM F3411)
│       └── track.py              # Track, Measurement, SensorType
├── shared/
│   ├── auth.py                   # Authentication utilities
│   ├── clock.py                  # Clock/FakeClock protocol
│   ├── geo.py                    # Lat/lon ↔ ENU conversion
│   ├── heartbeat.py              # Orchestrator heartbeat client
│   ├── lifecycle.py              # Graceful shutdown (SIGTERM/SIGINT)
│   ├── logging_setup.py          # Structured logging config
│   ├── rate_limit.py             # SlidingWindowLimiter, CircuitBreaker
│   └── utils.py                  # Misc helpers
└── tests/
    ├── conftest.py               # Shared fixtures (FakeClock, tracks, ROE)
    ├── decision/                 # Decision layer tests
    └── fusion/                   # Fusion layer tests
```
