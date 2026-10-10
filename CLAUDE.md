# CLAUDE.md

Guidance for Claude Code (and other coding agents) working in this repository.

## What Kyvern is

An audit layer for autonomous systems: it records the decisions a robot or AI
system makes into a signed, hash-linked JSONL chain, verifies that chain
offline, anchors it with RFC 3161 timestamps and reports on it. Customers
record their *own* system's decisions with `kyvern.record_decision()`; the
rule engine in `services/decision/` is an example decision stack, not the
product. Counter-UAS and weapons code is out of scope and lives elsewhere.

## Commands

```bash
pip install -r requirements.txt   # editable install with every extra
pytest                            # whole suite; tests needing an extra skip themselves
pytest tests/audit -q             # one area
ruff check .                      # must be clean; CI fails otherwise
pyright                           # type check of kyvern, cli, services, shared; must be clean
mkdocs serve                      # docs site (needs the docs extra)
python examples/ros2_safety_demo/run_demo.py --out <dir>   # end-to-end demo, no ROS2 needed
python examples/tamper_demo/run_demo.py --offline         # attacks on a log, and what catches them
```

CI (`.github/workflows/ci.yml`) runs ruff and pytest on Python 3.10–3.13,
pyright, a core-only install smoke test (`scripts/smoke_core_install.py`) and
the tests with only the `dev` extra. All are required checks on `main`. Core
code must not import an optional extra (`llm`, `mcp`, `docs`) at module level.
Tests that call the real RFC 3161 TSA run only with `KYVERN_TSA_E2E=1`.

## Layout

| Path | What lives there |
|------|------------------|
| `kyvern/__init__.py` | Public API: `record_decision`, `RecordedDecision` |
| `kyvern/audit/` | `AuditChainStore`: read-only chain loading, verification, search |
| `kyvern/mcp/` | `kyvern-mcp`, read-only stdio MCP server over a chain |
| `kyvern/sandwich/` | Dual-LLM (privileged / quarantined) pattern |
| `services/decision/audit_chain.py` | Signing, `canonical_json()`, verification, `record_decision` |
| `services/decision/chain_writer.py` | `ChainWriter`, the only code that appends to a chain |
| `services/decision/anchors.py`, `rfc3161_anchor.py` | Anchor protocol and RFC 3161 receipts |
| `services/decision/` (rest) | Example rule engine, LLM advisor, guardrails, `run_graph` |
| `services/integrations/` | ROS2 bridge and subscriber example |
| `shared/` | `schemas.py` (Decision, RuntimeEvent, RecordedDecision), `paths.py` (~/.kyvern) |
| `cli/` | `kyvern-verify`, `kyvern-report`, `kyvern-anchor` |
| `config/policies/default.yaml` | Example policy; a policy is any YAML with a `rules:` list |
| `docs/` | mkdocs site; `docs/superpowers/specs` and `plans` hold design docs |

## Invariants — do not break these

- **What is signed is frozen.** Changing record fields or `canonical_json()`
  breaks verification of every existing chain. Discuss in an issue first.
- **Only `ChainWriter` appends**, under a file lock with fsync. A decision
  that could not be recorded raises (`AuditWriteError`); never return it
  unrecorded.
- **Guardrails only downgrade** an action. The LLM advisor may only raise the
  rule engine's action, never to ENGAGE (`_reconcile_action` in `llm_graph.py`).
- **Verification fails closed.** A tampered, reordered, unknown-key or
  unparseable record must fail `kyvern-verify`, never be skipped. Tamper tests
  sweep every record field; extend them when you add a field.
- **Reports state only what was checked.** Rows the code cannot assess say
  NOT ASSESSED; never hard-code a PASS.
- Never commit signing keys, real chains, or anything from `~/.kyvern`.

## How to work here

- Test first: write the failing test, watch it fail, then make it pass. A
  test must fail when the rule it guards is removed.
- One change per branch and pull request; `main` is protected and merges only
  when every CI check passes.
- Do not push, merge, tag, bump the version or publish a release unless the
  maintainer asks for it.
- Add a line under `[Unreleased]` in `CHANGELOG.md` for anything a user would
  notice (Keep a Changelog format).
- Code, comments and docs are in English. Update README and `docs/` when
  behaviour changes.
- Design docs for bigger work go in `docs/superpowers/specs/YYYY-MM-DD-<topic>-design.md`,
  their implementation plans in `docs/superpowers/plans/`.

## Gotchas

- The editable install must point at this checkout. After moving the folder or
  bumping the version, run `pip install -e . --no-deps`; until then
  `test_report_version_matches_the_package_version` fails.
- `mcp` is capped below 2 (2.x renamed `FastMCP`).
- RFC 3161: the default TSA is IdenTrust. DigiCert, Sectigo, GlobalSign and
  Entrust responses do not parse in `rfc3161-client`. certifi holds a root
  with a non-positive serial, so roots are loaded one by one.
- `kyvern_home()` refuses to run when only the pre-rename `~/.kernel` exists,
  so a new signing key is never created silently.
- Environment variables: `KYVERN_CHAIN_PATH`, `KYVERN_DECISION_LLM_ENABLED`,
  `KYVERN_LLM_MODEL`.
- Without anchors, entries deleted from the end of a chain cannot be detected;
  `kyvern-verify --require-anchors` makes anchors mandatory, and `--max-lag`
  bounds how far an anchored entry can have been backdated.
- On Windows a running `kyvern-mcp.exe` locks the script, so `pip install -e .`
  fails until it stops; run the MCP server as `python -m kyvern.mcp.server`.
- Stacked pull requests: retarget a child PR to `main` before merging its base
  with branch deletion, or GitHub closes the child instead of retargeting it.
