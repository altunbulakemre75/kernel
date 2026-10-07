# Rename kernel → Kyvern Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename the project from `kernel` to Kyvern everywhere it is a live identifier, and add a guard so the move from `~/.kernel` to `~/.kyvern` can never silently replace the signing key.

**Architecture:** One new helper, `shared/paths.py::kyvern_home()`, becomes the only place that knows the per-user directory; it raises `LegacyHomeError` when only the pre-rename `~/.kernel` exists. The rename itself is mechanical: `git mv` for paths, a case-preserving `kernel → kyvern` swap for code and config, and a prose-aware swap for Markdown (prose says "Kyvern", code says `kyvern`).

**Tech Stack:** Python 3.10–3.13, pytest, ruff, setuptools (pyproject), git, PowerShell on Windows for the local steps.

**Spec:** `docs/superpowers/specs/2026-10-07-rename-kyvern-design.md`

**Branch:** `chore/rename-kyvern` (already created from `main` at `8ebed6b`; the spec is commit `71198eb`).

**`<scratchpad>`** below means `C:\Users\altun\AppData\Local\Temp\claude\C--Users-altun-Desktop-Yeni-klas-r-kernel\e0dd28f8-16c4-4728-a9f9-fe35f6b37298\scratchpad` — a directory outside the repo for one-off scripts and build output.

**Test count:** 215 passed, 3 skipped before this work; Task 1 adds 6 tests and rewrites 1, so the target is **221 passed, 3 skipped**.

---

## File map

| File | Change |
|---|---|
| `shared/paths.py` | **Create.** `kyvern_home()`, `LegacyHomeError`, the two directory-name constants. |
| `tests/test_paths.py` | **Create.** Guard tests and key-creation tests. |
| `services/decision/audit_chain.py` | `load_or_create_keypair()` takes its key directory from `kyvern_home()`. |
| `kernel/mcp/server.py` → `kyvern/mcp/server.py` | `--chain-file` and `--pubkey` defaults come from `kyvern_home()`; drop the unused `os` import. |
| `tests/mcp/test_server.py` | `test_parse_args_defaults` checks the exact defaults against a redirected home. |
| `kernel/` → `kyvern/` | `git mv`, then name swap. |
| `cli/kernel_verify.py`, `cli/kernel_report.py` → `cli/kyvern_*.py` | `git mv`, then name swap. |
| `tests/cli/test_kernel_verify.py`, `tests/cli/test_kernel_report.py` → `tests/cli/test_kyvern_*.py` | `git mv`, then name swap. |
| Every other tracked code/config file mentioning `kernel` (≈53 files, see Task 3) | Case-preserving swap. |
| `README.md`, `docs/**/*.md` except `docs/superpowers/` | Prose-aware swap plus three hand edits. |
| `mkdocs.yml`, `CHANGELOG.md` | Hand edits. |

Never touched: `docs/superpowers/specs/*` and `docs/superpowers/plans/*` other than this plan and the rename spec, and the CHANGELOG `[0.2.0]`/`[0.1.0]` entries.

---

### Task 1: Legacy home guard

**Files:**
- Create: `shared/paths.py`
- Create: `tests/test_paths.py`
- Modify: `services/decision/audit_chain.py:1-16`
- Modify: `kernel/mcp/server.py:1-30`
- Modify: `tests/mcp/test_server.py:1-16`

- [ ] **Step 1: Write the failing guard tests**

Create `tests/test_paths.py`:

```python
"""Tests for shared.paths — the per-user Kyvern directory and its pre-rename guard."""
from pathlib import Path

import pytest

from services.decision.audit_chain import load_or_create_keypair
from shared.paths import LegacyHomeError, kyvern_home


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    return tmp_path


def test_returns_kyvern_dir_when_nothing_exists(fake_home):
    assert kyvern_home() == fake_home / ".kyvern"
    # The helper only resolves the path; callers create it.
    assert not (fake_home / ".kyvern").exists()


def test_returns_kyvern_dir_when_it_exists(fake_home):
    (fake_home / ".kyvern").mkdir()
    assert kyvern_home() == fake_home / ".kyvern"


def test_prefers_kyvern_dir_when_both_exist(fake_home):
    (fake_home / ".kyvern").mkdir()
    (fake_home / ".kernel").mkdir()
    assert kyvern_home() == fake_home / ".kyvern"


def test_refuses_when_only_legacy_dir_exists(fake_home):
    (fake_home / ".kernel").mkdir()
    with pytest.raises(LegacyHomeError) as exc_info:
        kyvern_home()
    message = str(exc_info.value)
    assert str(fake_home / ".kernel") in message
    assert str(fake_home / ".kyvern") in message


def test_keypair_refuses_legacy_key_and_writes_nothing(fake_home):
    legacy_keys = fake_home / ".kernel" / "keys"
    legacy_keys.mkdir(parents=True)
    (legacy_keys / "signing.key").write_bytes(b"pre-rename key")
    with pytest.raises(LegacyHomeError):
        load_or_create_keypair()
    assert not (fake_home / ".kyvern").exists()


def test_keypair_created_under_kyvern_dir(fake_home):
    load_or_create_keypair()
    assert (fake_home / ".kyvern" / "keys" / "signing.key").is_file()
    assert (fake_home / ".kyvern" / "keys" / "signing.pub").is_file()
```

- [ ] **Step 2: Make the MCP defaults test exact and hermetic**

The current `test_parse_args_defaults` reads the real home directory, so it would hit the guard on a machine that still has `~/.kernel`. Make it check the exact paths against a redirected home instead.

In `tests/mcp/test_server.py`, add `from pathlib import Path` so the top reads:

```python
from pathlib import Path

import pytest

from kernel.mcp.errors import KernelMCPError
from kernel.mcp.server import build_app, parse_args
```

and replace `test_parse_args_defaults` with:

```python
def test_parse_args_defaults(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    ns = parse_args([])
    assert Path(ns.chain_file) == tmp_path / ".kyvern" / "chain.jsonl"
    assert Path(ns.pubkey) == tmp_path / ".kyvern" / "keys" / "signing.pub"
    assert ns.verify_on_query is True
```

`test_parse_args_no_verify` also calls `parse_args()`, so redirect its home the same way:

```python
def test_parse_args_no_verify(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    ns = parse_args(["--no-verify-on-query"])
    assert ns.verify_on_query is False
```

- [ ] **Step 3: Run the new tests to verify they fail**

Run: `python -m pytest -q -p no:cacheprovider tests/test_paths.py`
Expected: `ERROR collecting tests/test_paths.py` with `ModuleNotFoundError: No module named 'shared.paths'`.

Run: `python -m pytest -q -p no:cacheprovider tests/mcp/test_server.py::test_parse_args_defaults`
Expected: FAIL — `ns.chain_file` still comes from `os.path.expanduser("~/.kernel/chain.jsonl")`, which ignores the redirected `Path.home()`.

- [ ] **Step 4: Create `shared/paths.py`**

```python
"""
shared/paths.py — Where Kyvern keeps per-user state (signing keys, default chain).
"""

from __future__ import annotations

from pathlib import Path

HOME_DIR_NAME = ".kyvern"
LEGACY_HOME_DIR_NAME = ".kernel"  # used before the kernel -> Kyvern rename


class LegacyHomeError(RuntimeError):
    """Only the pre-rename ~/.kernel directory exists."""


def kyvern_home() -> Path:
    """Return ~/.kyvern, refusing to continue if only the pre-rename ~/.kernel exists.

    Without this check load_or_create_keypair() would find no key under ~/.kyvern
    and silently start signing with a brand-new one.
    """
    home = Path.home()
    current = home / HOME_DIR_NAME
    legacy = home / LEGACY_HOME_DIR_NAME
    if not current.exists() and legacy.exists():
        raise LegacyHomeError(
            f"Found {legacy} from before the kernel -> Kyvern rename, but {current} "
            f"does not exist. Move it to keep your signing key and chain: "
            f"mv {legacy} {current}"
        )
    return current
```

The message uses `->`, not `→`, so it prints on any console encoding.

- [ ] **Step 5: Use it in `load_or_create_keypair()`**

In `services/decision/audit_chain.py`, add the import next to the existing `shared` import:

```python
from shared.paths import kyvern_home
from shared.schemas import RuntimeEvent
```

and change the first line of `load_or_create_keypair()`:

```python
def load_or_create_keypair() -> ed25519.Ed25519PrivateKey:
    keys_dir = str(kyvern_home() / "keys")
```

Leave the rest of the function as it is.

- [ ] **Step 6: Use it for the MCP server defaults**

In `kernel/mcp/server.py`, remove `import os` (its only use was `expanduser`), add the import after the `kernel.mcp` imports:

```python
from kernel.audit import AuditChainStore
from kernel.mcp.errors import KernelMCPError
from kernel.mcp.resources import register_resources
from kernel.mcp.tools import register_tools
from shared.paths import kyvern_home
```

and replace the two defaults:

```python
    parser.add_argument(
        "--chain-file",
        dest="chain_file",
        default=str(kyvern_home() / "chain.jsonl"),
    )
    parser.add_argument(
        "--pubkey",
        dest="pubkey",
        default=str(kyvern_home() / "keys" / "signing.pub"),
    )
```

- [ ] **Step 7: Run the new tests to verify they pass**

Run: `python -m pytest -q -p no:cacheprovider tests/test_paths.py tests/mcp/test_server.py`
Expected: `12 passed` (6 in `test_paths.py`, 6 in `test_server.py`). These tests redirect `Path.home()`, so they pass even though this machine still has `~/.kernel`. Do not run the full suite yet: until Task 2 moves `~/.kernel`, tests that sign decisions through the real home directory hit the guard.

- [ ] **Step 8: Lint**

Run: `python -m ruff check .`
Expected: `All checks passed!` If it reports import-order (`I001`) findings, run `python -m ruff check . --fix` and re-run.

- [ ] **Step 9: Commit**

```bash
git add shared/paths.py tests/test_paths.py services/decision/audit_chain.py kernel/mcp/server.py tests/mcp/test_server.py
git commit -m "feat: refuse to run when only the pre-rename ~/.kernel exists

load_or_create_keypair() and the MCP server defaults now resolve the per-user
directory through shared.paths.kyvern_home(). If ~/.kyvern is missing but
~/.kernel exists, it raises LegacyHomeError instead of silently generating a
new signing key."
```

---

### Task 2: Move this machine's home directory

No commit. This keeps the existing signing key and lets the full test suite run again.

- [ ] **Step 1: Record the public key fingerprint**

Run (PowerShell):

```powershell
(Get-FileHash "$HOME\.kernel\keys\signing.pub" -Algorithm SHA256).Hash
```

Write the hash down.

- [ ] **Step 2: Move the directory**

Run:

```powershell
if (Test-Path "$HOME\.kyvern") { throw "~/.kyvern already exists; stop and inspect it" }
Move-Item "$HOME\.kernel" "$HOME\.kyvern"
```

Expected: no output.

- [ ] **Step 3: Verify the key is unchanged and the old directory is gone**

Run:

```powershell
(Get-FileHash "$HOME\.kyvern\keys\signing.pub" -Algorithm SHA256).Hash
Test-Path "$HOME\.kernel"
```

Expected: the same hash as Step 1, then `False`.

- [ ] **Step 4: Run the full suite**

Run: `python -m pytest -q -p no:cacheprovider`
Expected: `221 passed, 3 skipped`.

---

### Task 3: Rename in code, commands, env vars and URIs

**Files:** `kernel/` → `kyvern/`; `cli/kernel_*.py` → `cli/kyvern_*.py`; `tests/cli/test_kernel_*.py` → `tests/cli/test_kyvern_*.py`; every other tracked file (≈53) with suffix `.py .toml .txt .yaml .yml .json .cfg .ini` that mentions `kernel`, except `docs/**`, `README.md`, `CHANGELOG.md`, `mkdocs.yml`, `shared/paths.py` and `tests/test_paths.py`.

In code and config, every occurrence of `kernel` is the project name, including NATS subjects (`kernel.raw.*`, `kernel.tracks.active`), the ROS2 topic (`/kernel/decisions`), ROS2 node names, class names (`KernelMCPError`, `KernelDecisionPublisher`, `KernelDecisionVerifier`), the Claude Desktop config key, the demo directory (`kernel-demo`) and `FastMCP("kernel-test")` in tests. A case-preserving swap is therefore correct for all of them.

- [ ] **Step 1: Move the paths**

```bash
git mv kernel kyvern
git mv cli/kernel_verify.py cli/kyvern_verify.py
git mv cli/kernel_report.py cli/kyvern_report.py
git mv tests/cli/test_kernel_verify.py tests/cli/test_kyvern_verify.py
git mv tests/cli/test_kernel_report.py tests/cli/test_kyvern_report.py
```

Then remove any leftover untracked `kernel/` directory (only `__pycache__` can be left behind):

```powershell
if (Test-Path kernel) { if (git ls-files kernel) { throw "tracked files left in kernel/" } else { Remove-Item -Recurse -Force kernel } }
```

- [ ] **Step 2: Write the swap script**

Save as `<scratchpad>/rename_code.py` (outside the repo):

```python
"""One-off: case-preserving kernel -> kyvern swap in tracked code and config files."""
import subprocess
from pathlib import Path

SUFFIXES = {".py", ".toml", ".txt", ".yaml", ".yml", ".json", ".cfg", ".ini"}
SKIP_FILES = {"README.md", "CHANGELOG.md", "mkdocs.yml", "shared/paths.py", "tests/test_paths.py"}
SKIP_PREFIXES = ("docs/",)


def swap(text: str) -> str:
    return text.replace("KERNEL", "KYVERN").replace("Kernel", "Kyvern").replace("kernel", "kyvern")


tracked = subprocess.run(
    ["git", "ls-files"], capture_output=True, text=True, check=True
).stdout.splitlines()

changed = []
for name in tracked:
    if name in SKIP_FILES or name.startswith(SKIP_PREFIXES) or Path(name).suffix not in SUFFIXES:
        continue
    path = Path(name)
    old = path.read_bytes().decode("utf-8")  # bytes round-trip keeps CRLF/LF as they are
    new = swap(old)
    if new != old:
        path.write_bytes(new.encode("utf-8"))
        changed.append(name)

print(f"{len(changed)} files changed")
for name in changed:
    print("  " + name)
```

- [ ] **Step 3: Run it from the repo root**

Run: `python <scratchpad>/rename_code.py`
Expected: about 53 files changed, including `pyproject.toml`, `requirements.txt`, `config/policies/default.yaml`, `examples/mcp_claude_desktop_config.json`, everything under `kyvern/`, and the test files.

- [ ] **Step 4: Check for stragglers**

Run: `git grep -n -i kernel -- . ':!docs' ':!README.md' ':!CHANGELOG.md' ':!mkdocs.yml'`
Expected: matches only in `shared/paths.py` (constant, docstring, error message) and `tests/test_paths.py` (legacy directory in the tests).

Also confirm the entry points: `Select-String -Path pyproject.toml -Pattern 'kyvern'` must show `name = "kyvern"`, the three `kyvern-*` scripts pointing at `cli.kyvern_verify:main`, `cli.kyvern_report:main`, `kyvern.mcp.server:run`, and `"kyvern*"` in `packages.find`.

- [ ] **Step 5: Replace the stale editable install**

The global Python still has the old `kernel` distribution installed in editable mode. `--no-deps` keeps pip from replacing the newer local pydantic/numpy with the pins in `requirements.txt`.

```powershell
python -m pip uninstall -y kernel
if (Test-Path kernel.egg-info) { Remove-Item -Recurse -Force kernel.egg-info }
python -m pip install -e . --no-deps
```

Expected: `Successfully installed kyvern-0.1.0`.

- [ ] **Step 6: Run the full suite and lint**

Run: `python -m pytest -q -p no:cacheprovider`
Expected: `221 passed, 3 skipped`.

Run: `python -m ruff check .`
Expected: `All checks passed!`

- [ ] **Step 7: Check the commands**

```powershell
kyvern-verify --help; "exit=$LASTEXITCODE"
kyvern-report --help; "exit=$LASTEXITCODE"
kyvern-mcp --help; "exit=$LASTEXITCODE"
Get-Command kernel-verify -ErrorAction SilentlyContinue
```

Expected: three help texts, each followed by `exit=0`; the last line prints nothing.

- [ ] **Step 8: Commit**

```bash
git add -u
git commit -m "refactor: rename kernel to kyvern in code, commands, env vars and URIs

Package and import name kyvern, commands kyvern-verify/report/mcp, KYVERN_*
env vars, kyvern_* metrics, kyvern:// MCP URIs, kyvern.* NATS subjects,
/kyvern/decisions ROS2 topic, Kyvern* class names. NIZAM_* fallbacks are
unchanged."
```

`git add -u` stages the swapped files; the `git mv` renames are already staged.

---

### Task 4: Rename in the docs

**Files:**
- Modify: `README.md`, `docs/index.md`, `docs/architecture.md`, `docs/threat-model.md`, `docs/roadmap.md`, `docs/pilots.md`, `docs/compliance/eu_ai_act.md`, `docs/integrations/mcp.md`, `docs/integrations/ros2.md`, `docs/patterns/dual_llm_sandwich.md`
- Modify: `mkdocs.yml:1-4`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Remove the "PyPI `kernel` is unrelated" notes before the swap**

After the swap these would read "the `kyvern` package there is an unrelated project", which is false. Make these three edits first.

`README.md` and `docs/index.md` — replace

```
kernel is not published on PyPI yet (the `kernel` package there is an
unrelated project), so install from source:
```

with

```
Kyvern is not published on PyPI yet, so install from source:
```

`docs/integrations/mcp.md` — replace

```
1. **Install from source with the `mcp` extra** (kernel is not on PyPI yet;
   the `kernel` package there is an unrelated project):
```

with

```
1. **Install from source with the `mcp` extra** (Kyvern is not on PyPI yet):
```

- [ ] **Step 2: Write the prose-aware swap script**

Save as `<scratchpad>/rename_docs.py`:

```python
"""One-off: kernel -> Kyvern in prose, kernel -> kyvern in code, for README and docs/."""
import re
import subprocess
from pathlib import Path

# Inline code, link targets, autolinks/HTML and bare URLs stay code-like (lowercase).
CODE_LIKE = re.compile(r"(`[^`]*`|\]\([^)]*\)|<[^>]*>|https?://\S+)")
# The project name used as a word in prose: not glued to path or identifier characters,
# and not followed by ".something" (a module path like kernel.mcp).
PROSE_NAME = re.compile(r"(?<![\w./~:-])[Kk]ernel(?![\w/:-])(?!\.\w)")


def swap_code(text: str) -> str:
    return text.replace("KERNEL", "KYVERN").replace("Kernel", "Kyvern").replace("kernel", "kyvern")


def swap_prose(text: str) -> str:
    return swap_code(PROSE_NAME.sub("Kyvern", text))


def swap_line(line: str) -> str:
    parts = CODE_LIKE.split(line)  # odd indexes are the code-like matches
    return "".join(swap_code(p) if i % 2 else swap_prose(p) for i, p in enumerate(parts))


files = [
    f
    for f in subprocess.run(
        ["git", "ls-files", "README.md", "docs"], capture_output=True, text=True, check=True
    ).stdout.splitlines()
    if f.endswith(".md") and not f.startswith("docs/superpowers/")
]

for name in files:
    path = Path(name)
    old = path.read_bytes().decode("utf-8")
    out, in_fence = [], False
    for line in old.splitlines(keepends=True):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            out.append(swap_code(line))
        else:
            out.append(swap_code(line) if in_fence else swap_line(line))
    new = "".join(out)
    if new != old:
        path.write_bytes(new.encode("utf-8"))
        print("changed", name)
```

- [ ] **Step 3: Run it from the repo root**

Run: `python <scratchpad>/rename_docs.py`
Expected: `changed` lines for `README.md` and the nine `docs/` files listed above.

- [ ] **Step 4: Review every changed line by hand**

Run: `git diff -U0 -- README.md docs | Select-String '^\+[^+]'`
Read each line. Prose must say "Kyvern" (including headings, for example `# Kyvern`, and "Kyvern's"). Commands, paths, URLs, env vars and code must say `kyvern`/`KYVERN`. Fix anything that reads wrong with a direct edit, for example a sentence that now starts with lowercase `kyvern` outside code, or a diagram label inside a fenced block that should read "Kyvern".

- [ ] **Step 5: `mkdocs.yml`**

Replace lines 1–4 with:

```yaml
site_name: Kyvern
site_url: https://altunbulakemre75.github.io/kyvern
repo_url: https://github.com/altunbulakemre75/kyvern
repo_name: altunbulakemre75/kyvern
```

- [ ] **Step 6: `CHANGELOG.md`**

In the `[Unreleased]` section only:

1. Insert these bullets at the top of `### Changed`:

```markdown
- **Renamed the project from `kernel` to Kyvern** (the PyPI name `kernel`
  belongs to an unrelated package). Breaking for source checkouts:
  - package and import name `kyvern` (was `kernel`)
  - commands `kyvern-verify`, `kyvern-report`, `kyvern-mcp`
  - environment variables `KYVERN_*` (was `KERNEL_*`) and metrics `kyvern_*`
  - per-user directory `~/.kyvern` (was `~/.kernel`); run
    `mv ~/.kernel ~/.kyvern` to keep your signing key
  - MCP URIs `kyvern://...`, NATS subjects `kyvern.*`, ROS2 topic
    `/kyvern/decisions`
```

2. Append this bullet to the end of `### Added`:

```markdown
- Startup check that stops with a clear error when only the pre-rename
  `~/.kernel` directory exists, instead of silently generating a new
  signing key
```

3. In the existing `### Changed` bullets of `[Unreleased]`, change `kernel://stats/today` and `kernel://audit/recent` to `kyvern://stats/today` and `kyvern://audit/recent`.

4. Change the three compare/release links at the bottom of the file from `https://github.com/altunbulakemre75/kernel/` to `https://github.com/altunbulakemre75/kyvern/`.

Leave the `[0.2.0]` and `[0.1.0]` entries unchanged.

- [ ] **Step 7: Final straggler check**

Run: `git grep -n -i kernel -- . ':!docs/superpowers'`
Expected: only
- `CHANGELOG.md`: the `[0.2.0]` entries, and the new rename and `~/.kernel` bullets
- `shared/paths.py` and `tests/test_paths.py`

- [ ] **Step 8: Build the docs locally if mkdocs is installed (optional)**

Run: `python -m mkdocs build --strict` only if `python -m mkdocs --version` works. Warnings about `docs/superpowers` links already existed before this change; ignore them. Skip this step if mkdocs is not installed.

- [ ] **Step 9: Commit**

```bash
git add README.md docs mkdocs.yml CHANGELOG.md
git commit -m "docs: rename kernel to Kyvern in README, docs, mkdocs and CHANGELOG"
```

This plan and the spec are committed before Task 1, so `git add docs` stages only the renamed docs.

---

### Task 5: Acceptance checks, push and PR

- [ ] **Step 1: Wheel contents**

```powershell
$w = "<scratchpad>\wheel"
python -m pip wheel . --no-deps -w $w -q
python -c "import zipfile,glob; z=zipfile.ZipFile(glob.glob(r'$w\kyvern-*.whl')[0]); print(sorted({n.split('/')[0] for n in z.namelist() if not n.split('/')[0].endswith(('.dist-info','.data'))}))"
```

Expected: `['cli', 'kyvern', 'services', 'shared']` — no `kernel`.

- [ ] **Step 2: Commands in a throwaway venv**

```powershell
$v = "<scratchpad>\venv-kyvern"
python -m venv --system-site-packages $v
& "$v\Scripts\python.exe" -m pip install -q -e . --no-deps
& "$v\Scripts\kyvern-verify.exe" --help | Out-Null; "verify=$LASTEXITCODE"
& "$v\Scripts\kyvern-report.exe" --help | Out-Null; "report=$LASTEXITCODE"
& "$v\Scripts\kyvern-mcp.exe" --help | Out-Null; "mcp=$LASTEXITCODE"
Remove-Item -Recurse -Force $v, $w
```

Expected: `verify=0`, `report=0`, `mcp=0`.

- [ ] **Step 3: Full suite and lint once more**

Run: `python -m pytest -q -p no:cacheprovider` → `221 passed, 3 skipped`
Run: `python -m ruff check .` → `All checks passed!`

- [ ] **Step 4: Push and open the PR**

```bash
git push -u origin chore/rename-kyvern
gh pr create --repo altunbulakemre75/kernel --base main --head chore/rename-kyvern --title "Rename kernel to Kyvern" --body-file <scratchpad>/pr_body.md
```

Write `<scratchpad>/pr_body.md` with this content, filling in the two numbers from Steps 1–3:

```markdown
## Summary
- Rename the project from `kernel` to **Kyvern**: the PyPI name `kernel` belongs to an unrelated package.
- Everywhere it is a live identifier: package/import `kyvern`, commands `kyvern-verify`/`kyvern-report`/`kyvern-mcp`, `KYVERN_*` env vars, `kyvern_*` metrics, `~/.kyvern`, `kyvern://` MCP URIs, `kyvern.*` NATS subjects, `/kyvern/decisions` ROS2 topic, docs and mkdocs.
- New guard (`shared/paths.py::kyvern_home()`): if only the pre-rename `~/.kernel` exists, Kyvern stops with a clear "move it" error instead of silently generating a new signing key.
- Historical specs/plans under `docs/superpowers/` and past CHANGELOG entries are unchanged.
- Spec: `docs/superpowers/specs/2026-10-07-rename-kyvern-design.md`; plan: `docs/superpowers/plans/2026-10-07-rename-kyvern.md`.

## Breaking changes (source checkouts)
- Reinstall: `pip uninstall kernel && pip install -e ".[mcp]"`
- Rename `KERNEL_*` env vars to `KYVERN_*`
- `mv ~/.kernel ~/.kyvern` to keep the signing key

## Merge order
Rename the GitHub repository to `kyvern` (Settings → Repository name) right before merging. GitHub redirects the old `/kernel` URLs.

## Test plan
- [x] <N> passed, 3 skipped; `ruff check .` clean
- [x] Wheel contains `cli`, `kyvern`, `services`, `shared` (no `kernel`)
- [x] `kyvern-verify`, `kyvern-report`, `kyvern-mcp` `--help` exit 0 in a fresh venv
- [x] Local `~/.kernel` moved to `~/.kyvern`; signing key fingerprint unchanged
- [ ] CI green on this PR

🤖 Generated with [Claude Code](https://claude.com/claude-code)
```

- [ ] **Step 5: Hand over**

Report the PR link and CI result. The user renames the repository and merges.

---

### Task 6: After the merge

- [ ] **Step 1: Point the local remote at the new name**

```bash
git remote set-url origin https://github.com/altunbulakemre75/kyvern.git
git fetch origin
git checkout main
git merge --ff-only origin/main
```

- [ ] **Step 2: Check CI on `main`**

Run: `gh run list --repo altunbulakemre75/kyvern --branch main --limit 2`
Expected: the `CI` run for the merge commit is green. The `Docs` run still fails with the pre-existing 403 (GITHUB_TOKEN is read-only); that is a separate fix.
