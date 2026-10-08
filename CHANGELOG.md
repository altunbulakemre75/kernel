# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Fixed
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

[Unreleased]: https://github.com/altunbulakemre75/kyvern/compare/v0.3.2...HEAD
[0.3.2]: https://github.com/altunbulakemre75/kyvern/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/altunbulakemre75/kyvern/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/altunbulakemre75/kyvern/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/altunbulakemre75/kyvern/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/altunbulakemre75/kyvern/releases/tag/v0.1.0
