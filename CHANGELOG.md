# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- A public or signing key that is not Ed25519 (an RSA or P-256 key, say) is
  rejected with "… is not an Ed25519 public key" by `kyvern-verify`,
  `kyvern-report` and `kyvern-mcp`, and with "… is not an Ed25519 private
  key" when it is `~/.kyvern/keys/signing.key`; they used to stop with a
  Python traceback
- A malformed receipts file (a line that is not JSON, a receipt that is not
  an object or has no integer `chain_index` or `payload_hash` string) fails
  `kyvern-verify` with "receipt N: malformed" for each such receipt instead
  of a Python traceback
- An LLM advisor answer with a missing or invalid field (no `threat_level`,
  a `confidence` that is not a number between 0 and 1, say) no longer stops
  `run_graph` with an exception. Claude's and Ollama's answers go through
  the same check: an invalid value gets a safe default (an action outside
  the schema becomes `log`), and the answer is still recorded as given

## [0.4.0] — 2026-10-08

### Added
- CONTRIBUTING.md, SECURITY.md (private vulnerability reporting through
  GitHub), CODE_OF_CONDUCT.md, issue and pull request templates, a NOTICE
  file, and project URLs in `pyproject.toml`
- `kyvern.record_decision()` records a decision your own system made (a
  robot's safety controller, a planner, an operator) into the signed chain:
  the action, who decided, the reasoning, the inputs it was based on (up to
  64 KB), the rule that fired and, with `policy_path=`, the version of your
  policy. The record (`RecordedDecision`, `record_type: "decision"`) is
  checked against `--policy` by `kyvern-verify` and `kyvern-report` like
  any decision. A policy is any YAML file with a `rules:` list
- `kyvern-verify` lists recorded decisions as
  `action=STOP rule_id=... source=...`; `kyvern-report`'s Article 12 checks
  ask them for inputs and reasoning instead of a threat level, and its
  threat-level table covers only decisions that record one
- `examples/ros2_safety_demo`: a robot's own safety controller (stop / slow /
  continue from the closest obstacle, thresholds in its own policy file)
  recording each change of action with `record_decision()`, as a ROS2 node
  (`/scan` in, `/safety/action` out) and as a scenario that runs without
  ROS2 and ends with `kyvern-verify` and `kyvern-report`
- `kyvern-verify --require-anchors` fails a chain that has no valid RFC 3161
  receipt. Without receipts, entries deleted from the end of a chain cannot
  be detected (the shorter chain still verifies); the README and the threat
  model now say so. The JSON output has an `anchors_required` key

### Changed
- A decision's `source` is `llm_advisor` only when the LLM advisor raised the
  rule engine's action; it used to be `llm_advisor` whenever the LLM
  answered. Whether the LLM was consulted is in `llm_provider` and
  `llm_raw_response`
- The Anthropic model for the LLM advisor is read from `KYVERN_LLM_MODEL`.
  The pre-rename variables `NIZAM_LLM_MODEL` and
  `NIZAM_DECISION_LLM_ENABLED` are no longer read; use `KYVERN_LLM_MODEL`
  and `KYVERN_DECISION_LLM_ENABLED`
- CI also runs the tests on Python 3.13
- `kyvern-report`'s Article 12 and 14 tables are checks run on the chain
  instead of rows that always said PASS. Each row is PASS/FAIL with counts,
  NOT ASSESSED where a chain cannot show it (automatic recording, operator
  override, human interventions when none are recorded), N/A or INFO; rows
  computed from the records of a chain that fails integrity are NOT
  ASSESSED. Guardrail downgrades are reported as automated checks, not as
  human interventions. The report fingerprint also covers each check's
  result
- The report, README and `docs/compliance/eu_ai_act.md` describe evidence
  that supports an assessment, not compliance: the retention row says logs
  must be kept for at least six months (Art. 19(1), 26(6)) instead of ten
  years, and the docs no longer say that Kyvern blocks escalation until an
  operator approves (it records that approval was required)

### Removed
- The counter-UAS components moved to a separate private repository: sensor
  adapters (`services/detectors`), multi-sensor tracking (`services/fusion`,
  `services/schemas`), autonomy (`services/autonomy`: intercept planner,
  MAVSDK sender, geofence), the `shared/` helpers only they used (`clock`,
  `geo`, `rate_limit`, `lifecycle`, `heartbeat`, `logging_setup`, `utils`)
  and the `fusion` extra. Kyvern's core did not depend on them;
  `haversine_m`, the one function the guardrails used, now lives in
  `services/decision/guardrails.py`
- `services/decision/llm_advisor.py` (`query_llm_advisor`, `reconcile`):
  nothing called it; `run_graph()` reconciles the LLM's answer in
  `llm_graph._reconcile_action`
- `kyvern/mcp/schemas.py`: Pydantic models no module imported (the MCP tools
  return plain dicts)
- `AgentName`, `TaskRequest`, `AgentResult` and `OrchestratorResponse` from
  `shared/schemas.py`: unused models from the private deployment's orchestrator

### Fixed
- `LICENSE` was not the Apache License 2.0 text: several definitions and
  terms had been reworded or left out (GitHub could not identify it). It is
  now the verbatim license text; the copyright notice is in `NOTICE`
- `kyvern-verify`, `kyvern-report` and MCP `verify_chain` crashed on a
  tampered record holding a number, list or object in `timestamp_iso`,
  `key_id`, `chain_index`, `guardrails_triggered` or `roe_reference`; they now
  report the chain as failed
- MCP `verify_chain` reported `OK` for a range with no entries; it now
  reports `UNKNOWN`. A range is taken by entry position, so an entry whose
  `chain_index` was removed or rewritten stays in the range and fails it
  (it used to drop out, and the range reported `OK`)
- Tests: the LLM reconciliation `run_graph()` uses (`_reconcile_action`: no
  ENGAGE, no downgrade) had no test, while five tests covered the unused
  `llm_advisor.reconcile`; the friendly-zone test passed with the guardrail
  switched off. Both now fail when the rule they guard is removed
- Docs: `retrieve_roe` is a hook for a policy-retrieval module this
  repository does not ship (it passes the state through), `classify` uses
  the rule engine only, and the LLM ceiling is enforced in `llm_graph.py`

## [0.3.2] — 2026-10-08

### Changed
- `kyvern-verify` and `kyvern-report` accept `--policy` more than once, for a
  chain that spans a policy update. Every Decision must be bound to one of the
  given policies; the output says how many Decisions each policy covers, and
  lists Decisions recorded without a policy or under a policy that was not
  given, with their chain positions. The policy check also fails for a chain
  with no Decision and for a chain that fails the integrity check. The same
  policy given twice counts once
- `kyvern-verify`, `kyvern-report` and their JSON output count Decisions and
  RuntimeEvents separately; RuntimeEvents are listed by `event_type` and
  `source` instead of as decisions with action `UNKNOWN`
- `kyvern-verify --json` adds `decision_count`, `runtime_event_count`,
  `policy_version_ids`, `decisions_per_policy`, `unbound_decisions` and
  `unknown_policy_decisions`, also in the output for an empty chain file.
  `policy_version_id` is `null` when more than one policy is given
- `kyvern-verify`'s policy line reads `✓ Policy match: <version> (<file> @
  <time>): <n> decisions`, one line per policy
- `kyvern-report` checks the chain against `--policy`: the Article 14
  "Verifiable policy deployment" row is computed instead of always PASS, and
  the exit code is 1 when the policy check fails (the PDF is still written).
  The status line adds `[policy: OK|FAILED]` after `[chain: ...]`
- `kyvern-report`'s fingerprint covers the RuntimeEvent count and the policy
  check result, and its decision count no longer includes RuntimeEvents
- `append_runtime_event()`'s `policy_version_id` is optional; it is shown but
  not checked against a policy

### Fixed
- `kyvern-report` crashed on decisions recorded without a policy
  (`policy_version_id` null) and wrote no PDF
- `kyvern-report` crashed on a `policy_version_id` that is not text (a
  tampered record), and on `--system-id`, `--operator`, `--period` or chain
  text containing ReportLab markup such as `<font>`; that text is now printed
  as written
- MCP `verify_chain` reported a valid chain as `BROKEN` for any range that did
  not start at entry 0; a range is now checked from its link to the entry
  before it (`verify_chain()` and `describe_chain_failure()` take an optional
  `prev_hash`)
- The test suite runs with only the `dev` extra installed: fusion and MCP
  tests skip themselves when their extra is missing, instead of
  `tests/conftest.py` failing to import the fusion dependencies (numpy,
  filterpy) and stopping the whole run. CI runs this configuration.

## [0.3.1] — 2026-10-07

### Changed
- Dependencies are declared in `pyproject.toml`: a light core (cryptography,
  pydantic, pyyaml, filelock, rfc3161-client, certifi, reportlab, httpx) plus
  extras `fusion`, `llm`, `mcp`, `dev`, `docs`. `pydantic` is no longer pinned
  to 2.9.2 and `numpy` is no longer capped below 2 (the cap made `pip install .`
  fail on Python 3.13 without a C compiler). `requirements.txt` installs the
  full development environment
- The `mcp` extra is capped below 2 (`mcp>=1.12,<2`): mcp 2.x renamed
  `FastMCP` to `MCPServer`, which breaks `kyvern-mcp`

### Removed
- Unused dependencies: fastapi, uvicorn, pydantic-settings, sqlalchemy,
  alembic, PyJWT, passlib, python-multipart, python-dotenv, scikit-learn,
  joblib, opentelemetry-sdk, opentelemetry-exporter-otlp-proto-grpc,
  opentelemetry-instrumentation-fastapi
- `shared/auth.py` (JWT helpers from the private deployment's web API; unused)

## [0.3.0] — 2026-10-07

### Added
- RuntimeEvent schema for upstream evidence events (sensor monitors, guard
  middleware, external adapters); signed verbatim into the audit chain
  alongside Decisions
- `append_runtime_event()` function for adding upstream events to the chain
- Mixed-entry chain verification (Decision + RuntimeEvent), single shared
  `chain_index` counter, polymorphic `verify_chain()`
- MCP `query_events` field-aware filters: `event_type`/`source` return only
  RuntimeEvents; `action`/`threat_level` return only Decisions
- `PayloadTooLargeError` (64KB RuntimeEvent payload limit — asymmetric
  protection vs Decision, since upstream sources are less controlled)
- `verify_runtime_event()` thin alias over `verify_decision()`
- Startup check that stops with a clear error when only the pre-rename
  `~/.kernel` directory exists, instead of silently generating a new
  signing key
- `ChainWriter`: one inter-process-locked, fsynced append path for Decisions
  and RuntimeEvents; refuses to append after a corrupt chain tail
- Signed `key_id` on every chain entry; `Keyring` and repeatable `--pubkey`
  in `kyvern-verify`, `kyvern-report` and `kyvern-mcp` for chains signed by
  several keys; verification failures name their reason
- `run_graph(chain_path=...)` / `decide_full(chain_path=...)` and
  `KYVERN_CHAIN_PATH`
- External anchoring of the chain head: `kyvern-anchor` stores RFC 3161
  timestamps (IdenTrust by default) in `<chain stem>.anchors.jsonl`;
  `kyvern-verify` checks them (`--anchors`, `--tsa-root`) and fails when an
  anchored entry was rewritten; generic `Anchor` protocol for other anchor
  types. New dependencies: `rfc3161-client`, `certifi`

### Changed
- **Decisions are now recorded in the JSONL audit chain**
  (`~/.kyvern/chain.jsonl` by default), the same file the verifiers read.
  Breaking:
  - `run_graph()` / `decide_full()` raise `AuditWriteError` when a decision
    cannot be recorded, instead of returning it
  - Postgres recording, `KYVERN_DB_DSN` and the `asyncpg` dependency are removed
  - the signing key is no longer auto-created next to a non-empty chain
  - chains containing `key_id` need this version to verify
- **Renamed the project from `kernel` to Kyvern** (the PyPI name `kernel`
  belongs to an unrelated package). Breaking for source checkouts:
  - package and import name `kyvern` (was `kernel`)
  - commands `kyvern-verify`, `kyvern-report`, `kyvern-mcp`
  - environment variables `KYVERN_*` (was `KERNEL_*`) and metrics `kyvern_*`
  - per-user directory `~/.kyvern` (was `~/.kernel`); run
    `mv ~/.kernel ~/.kyvern` to keep your signing key
  - MCP URIs `kyvern://...`, NATS subjects `kyvern.*`, ROS2 topic
    `/kyvern/decisions`
- MCP `EventSummary` (`query_events`) and `SearchHit` (`search_events`)
  output: `action` is now nullable and, like `threat_level`, is `null` for
  RuntimeEvent records; new fields `record_type`, `event_type`, `source`
- MCP `get_stats` and `kyvern://stats/today`: new `by_record_type` and
  `by_event_type` fields; `action_distribution` and `threat_distribution`
  now count Decision records only
- `kyvern://audit/recent`: entries now include `record_type`, `event_type`
  and `source` (same shape as `query_events`); `action` is `null` instead
  of `""` for RuntimeEvent records

## [0.2.0] — 2026-05-26

### Added
- Ed25519 audit chain with SHA-256 hash linking (verifiable via kernel-verify)
- Policy versioning: SHA-256 content hash bound to every Decision
- ROS2 publisher bridge for live deployment (`services/integrations/ros2_bridge.py`)
- EU AI Act Article 12/14 compliance PDF report generator (`kernel-report` CLI)
- Dual-LLM Sandwich pattern (`kernel.sandwich`) — P-LLM/Q-LLM separation
- MCP server for natural-language audit chain queries (`kernel-mcp`)
- Threat model documentation (`docs/threat-model.md`)
- Pilot program landing page (`docs/pilots.md`)
- GitHub Actions CI (ruff + pytest, Python 3.10-3.12)
- MkDocs Material documentation site

### Changed
- README.md restructured around 4 capabilities + compliance evidence
- `services/decision/audit_chain.py` exposes `verify_decision_against_policy`

### Security
- Documented attack surface: insider tampering defended; key compromise
  is operator responsibility (HSM/KMS recommended)

## [0.1.0] — 2026-04-15

Initial open-core extraction.

[Unreleased]: https://github.com/altunbulakemre75/kyvern/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/altunbulakemre75/kyvern/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/altunbulakemre75/kyvern/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/altunbulakemre75/kyvern/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/altunbulakemre75/kyvern/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/altunbulakemre75/kyvern/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/altunbulakemre75/kyvern/releases/tag/v0.1.0
