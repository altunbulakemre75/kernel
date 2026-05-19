# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/altunbulakemre75/kernel/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/altunbulakemre75/kernel/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/altunbulakemre75/kernel/releases/tag/v0.1.0
