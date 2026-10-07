# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Changed
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

[Unreleased]: https://github.com/altunbulakemre75/kyvern/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/altunbulakemre75/kyvern/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/altunbulakemre75/kyvern/releases/tag/v0.1.0
