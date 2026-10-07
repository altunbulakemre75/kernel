# Rename: kernel → Kyvern

**Date:** 2026-10-07
**Status:** Approved in conversation, awaiting review of this written spec
**Scope:** Rename the project from `kernel` to Kyvern everywhere it is a live identifier (distribution, import package, CLI commands, env vars, metrics, home directory, MCP URIs, docs, GitHub repo), plus one guard that stops a silent signing-key swap caused by the home-directory move.
**Out of scope:** Any other behaviour change, including the fail-open handling in `llm_graph.finalize` (that is v0.3.0 work), the legacy `NIZAM_*` fallbacks, the Docs workflow permissions fix, and publishing to PyPI.

---

## 1. Why

The PyPI name `kernel` belongs to an unrelated company, so `pip install kernel` installs someone else's SDK, and the `kernel` import name would collide with that package if both were installed. The project needs a name it can own before it is published or shown to pilot users.

## 2. Decisions

| Decision | Choice | Notes |
|---|---|---|
| Name | **Kyvern** in prose, `kyvern` in code, commands and package metadata | Chosen by the user. |
| Similarity to Kyverno | Accepted | Kyverno is a CNCF graduated policy engine (~8.2k stars) one letter away, in the adjacent policy/compliance space; web searches for "Kyvern" return Kyverno, and the GitHub username `kyvern` is taken. The user chose Kyvern knowing this. |
| Rename depth | Everywhere | Cheapest now, while there are no external users. |
| Old names (`KERNEL_*`, `~/.kernel`) | Clean break plus a guard | Old names are no longer read. The guard in §5 prevents the one dangerous failure mode. |

Availability on 2026-10-07: `kyvern` is free on PyPI and npm. The PyPI name is not reserved until a first upload.

## 3. Rename map

| Today | After |
|---|---|
| `[project] name = "kernel"` | `name = "kyvern"` |
| `kernel/` package (`from kernel.mcp ...`) | `kyvern/` (moved with `git mv` so history follows) |
| `cli/kernel_verify.py`, `cli/kernel_report.py` | `cli/kyvern_verify.py`, `cli/kyvern_report.py` |
| `kernel-verify`, `kernel-report`, `kernel-mcp` | `kyvern-verify`, `kyvern-report`, `kyvern-mcp` |
| `KERNEL_DB_DSN`, `KERNEL_DECISION_LLM_ENABLED` | `KYVERN_DB_DSN`, `KYVERN_DECISION_LLM_ENABLED` |
| `KERNEL_MCP_E2E`, `KERNEL_SANDWICH_E2E` (test gates) | `KYVERN_MCP_E2E`, `KYVERN_SANDWICH_E2E` |
| Prometheus metrics `kernel_*` | `kyvern_*` |
| ROS2 node names `kernel_decision_publisher`, `kernel_decision_verifier` | `kyvern_decision_publisher`, `kyvern_decision_verifier` |
| ROS2 topic `/kernel/decisions` | `/kyvern/decisions` |
| NATS subjects `kernel.raw.*`, `kernel.tracks.active` | `kyvern.raw.*`, `kyvern.tracks.active` |
| Classes `KernelMCPError`, `KernelDecisionPublisher`, `KernelDecisionVerifier` | `KyvernMCPError`, `KyvernDecisionPublisher`, `KyvernDecisionVerifier` |
| Claude Desktop config key `"kernel"`, demo directory `kernel-demo` | `"kyvern"`, `kyvern-demo` |
| `~/.kernel/keys/`, `~/.kernel/chain.jsonl` | `~/.kyvern/keys/`, `~/.kyvern/chain.jsonl` |
| MCP server name `FastMCP("kernel")` | `FastMCP("kyvern")` |
| MCP URIs `kernel://audit/recent` etc. | `kyvern://audit/recent` etc. |
| Test files `tests/cli/test_kernel_*.py` | `tests/cli/test_kyvern_*.py` |
| README, `docs/*.md`, `docs/integrations/*.md`, `mkdocs.yml`, `examples/mcp_claude_desktop_config.json`, demo script output | Kyvern / `kyvern` |
| `site_url`, `repo_url` in `mkdocs.yml` | `.../kyvern` |

`NIZAM_*` fallbacks keep working exactly as today; only the `KERNEL_*` name in front of them changes (for example `os.getenv("KYVERN_DB_DSN", os.getenv("NIZAM_DB_DSN"))`).

## 4. Not renamed

- `docs/superpowers/specs/` and `docs/superpowers/plans/` written before this spec: historical records, left as they are.
- Past CHANGELOG entries. A new `[Unreleased]` → `Changed` entry records the rename and the breaking changes (package, commands, env vars, home directory, URIs).
- Generic uses of the word "kernel" that are not the project name, if any turn up.

## 5. Legacy home guard

**Problem.** `services/decision/audit_chain.py::load_or_create_keypair()` generates a new key whenever it finds none. After the rename it looks in `~/.kyvern/keys/`, so on any machine that still has `~/.kernel/keys/signing.key` it would silently start signing with a brand-new key. New records would then verify only against the new public key, older chains only against the old one, and nothing would say so. This machine has such a key (created 2026-05-16).

**Behaviour.** A single helper resolves the home directory:

```python
# shared/paths.py
class LegacyHomeError(RuntimeError): ...

def kyvern_home() -> Path:
    """Return ~/.kyvern; refuse to continue if only the pre-rename ~/.kernel exists."""
```

| `~/.kyvern` | `~/.kernel` | Result |
|---|---|---|
| exists | any | return `~/.kyvern` |
| missing | missing | return `~/.kyvern` (callers create it as today) |
| missing | exists | raise `LegacyHomeError` |

The error message names both absolute paths and the fix, for example: `Found <home>/.kernel from before the kernel → Kyvern rename, but <home>/.kyvern does not exist. Move it to keep your signing key and chain: mv <home>/.kernel <home>/.kyvern`.

The helper never moves, copies or deletes anything itself. It uses `Path.home()` so tests can redirect it.

**Callers.**
- `load_or_create_keypair()` builds its key directory from `kyvern_home()`. When the guard raises, no key file is written.
- `kyvern/mcp/server.py` builds its `--chain` and `--pubkey` defaults from `kyvern_home()`, so `kyvern-mcp` exits with the error message instead of starting on an empty path.

**Interaction with the live pipeline.** `llm_graph.finalize` wraps signing in `try/except` and only logs a warning. If the guard raises there, the decision is returned unsigned with a `decision signing failed` warning: no key is swapped, but the decision is not blocked. Making that path fail-closed is v0.3.0 work and is deliberately not changed here.

**Tests (written first).**
1. Only `~/.kernel` exists → `kyvern_home()` raises `LegacyHomeError`, and the message contains both paths.
2. Only `~/.kernel/keys/signing.key` exists → `load_or_create_keypair()` raises and creates no file under `~/.kyvern`.
3. Both directories exist → returns `~/.kyvern`, no error.
4. Neither exists → returns `~/.kyvern`, no error.
5. `kyvern-mcp` argument defaults resolve under `~/.kyvern`.

## 6. Local machine migration

Done during implementation, after the guard lands:
1. Record the SHA-256 of `~/.kernel/keys/signing.pub`.
2. Move `~/.kernel` to `~/.kyvern`.
3. Confirm the SHA-256 of `~/.kyvern/keys/signing.pub` is unchanged and that `~/.kernel` is gone.
4. Replace the stale editable install: `pip uninstall kernel`, then `pip install -e .` so the `kyvern-*` commands are registered and the old `kernel-*` commands disappear.

## 7. Delivery

- Branch `chore/rename-kyvern` from `main` (after `8ebed6b`).
- Commits, in order:
  1. This spec.
  2. Legacy home guard (§5), test first.
  3. Code rename (§3, everything except prose docs).
  4. Docs rename (README, docs, mkdocs, CHANGELOG, example config).
- Claude opens the PR; the user merges it.
- Order around the merge: the user renames the GitHub repository to `kyvern` (Settings → Repository name) right before merging. GitHub redirects the old `/kernel` URLs, so Issue #1, the PR history and external links keep working as long as no new repo named `kernel` is created under the account. Afterwards Claude points the local `origin` remote at the new URL.

## 8. Acceptance criteria

- `pytest`: all existing tests pass (215 passed, 3 skipped before this work), plus the new guard tests.
- `ruff check .` is clean.
- A case-insensitive search for the whole word `kernel` outside `docs/superpowers/` and past CHANGELOG entries finds only intentional references: the CHANGELOG rename note, the guard's legacy-path constant, its error message and its tests.
- The built wheel contains a top-level `kyvern/` package and no top-level `kernel/` package.
- In a throwaway venv with an editable install, `kyvern-verify --help`, `kyvern-report --help` and `kyvern-mcp --help` all exit 0.
- CI on the PR is green on Python 3.10–3.12.
- After §6, the key fingerprint is unchanged.

## 9. Risks

- **Confusion with Kyverno**, accepted (see §2).
- **PyPI name not reserved.** Someone else could register `kyvern` before the first upload. Reserving it would mean publishing to PyPI, which is a separate decision for the user.
- **Unsigned decisions on machines with an unmigrated `~/.kernel`** until v0.3.0 makes signing fail-closed (see §5). Mitigated by the clear error message, the CHANGELOG note and the local migration in §6.
