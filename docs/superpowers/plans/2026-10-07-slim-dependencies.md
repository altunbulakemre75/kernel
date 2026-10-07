# Slim Dependencies Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `pip install .` installs only what the decision/audit core imports; sensor fusion, LLM, MCP and dev tooling become extras; unused packages and the dead `shared/auth.py` go away; CI proves the core works without extras.

**Architecture:** Dependencies move from `requirements.txt` (read through `dynamic`) into `[project] dependencies` and `[project.optional-dependencies]` in `pyproject.toml`. `requirements.txt` becomes a one-line full-dev convenience. A new `scripts/smoke_core_install.py` runs the decision pipeline and CLIs from a core-only install; a new CI job runs it.

**Tech Stack:** setuptools/pyproject, pip, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-07-slim-dependencies-design.md` (commit `1cfe1d0`)
**Branch:** `chore/slim-deps` from `main` at `ce8e547`.

**`<scratchpad>`** = `C:\Users\altun\AppData\Local\Temp\claude\C--Users-altun-Desktop-Yeni-klas-r-kernel\e0dd28f8-16c4-4728-a9f9-fe35f6b37298\scratchpad`; **`<repo>`** = `C:\Users\altun\Desktop\Yeni klasör\kernel`.

**Test count before:** 283 passed, 4 skipped. This plan adds no pytest tests; its checks are the smoke script, the dry-run package count and the existing suite.

---

### Task 1: Measure the current install (baseline, no commit)

- [ ] **Step 1: Count packages a clean `pip install .` would install today**

```powershell
$sp = "<scratchpad>"
python -m venv "$sp\venv-count"
& "$sp\venv-count\Scripts\python.exe" -m pip install -q --disable-pip-version-check --dry-run --ignore-installed --report "$sp\deps-before.json" .
python -c "import json; r=json.load(open(r'$sp\deps-before.json', encoding='utf-8')); names=sorted(i['metadata']['name'] for i in r['install']); print(len(names)); print(', '.join(names))"
```

Expected: a count in the dozens (the project itself is included in the list). Write the number down for the PR.

---

### Task 2: Core smoke script

**Files:** Create `scripts/smoke_core_install.py`

- [ ] **Step 1: Write the script**

```python
"""Smoke test for a core-only install (`pip install .`, no extras).

Run it from outside the repository so imports resolve to the installed package:

    cd /tmp && python <repo>/scripts/smoke_core_install.py

It runs one decision through the live pipeline into a temporary chain, verifies
the chain, and runs the CLIs' --help. It fails if any of that needs an extra.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        os.environ["HOME"] = str(home)         # Path.home() on POSIX
        os.environ["USERPROFILE"] = str(home)  # Path.home() on Windows
        chain = home / "chain.jsonl"

        import cli.kyvern_anchor  # noqa: F401
        import cli.kyvern_report  # noqa: F401
        import cli.kyvern_verify  # noqa: F401
        from services.decision.audit_chain import Keyring, verify_chain
        from services.decision.schemas import Action, ROERule, ThreatLevel
        from services.decision.threat_graph import decide_full

        rules = [
            ROERule(rule_id=f"r_{level.value}", description="smoke", when_threat_level=level,
                    requires_operator_approval=False, action=Action.LOG)
            for level in ThreatLevel
        ]
        track = {
            "track_id": "smoke", "latitude": 40.0, "longitude": 33.0, "altitude": 100.0,
            "confidence": 0.9, "hits": 10, "vx": 5.0, "vy": 0.0, "vz": 0.0,
            "x": 0.0, "y": 0.0, "z": 100.0, "sources": ["camera"],
        }
        decision = decide_full(track, rules, chain_path=chain)
        entries = [json.loads(line) for line in chain.read_text(encoding="utf-8").splitlines()]
        keys = Keyring.from_pem_files([home / ".kyvern" / "keys" / "signing.pub"])
        if verify_chain(entries, keys) != (True, None) or decision.chain_index != 0:
            print("smoke: the recorded decision does not verify", file=sys.stderr)
            return 1

        bin_dir = Path(sys.executable).parent
        for command in ("kyvern-verify", "kyvern-report", "kyvern-anchor"):
            subprocess.run([str(bin_dir / command), "--help"], check=True, capture_output=True)

    print("core install OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Lint**

Run: `python -m ruff check scripts/smoke_core_install.py` → `All checks passed!` (apply `--fix` for import order if needed).

(The script is exercised in Task 4, after the dependency change, in a venv with only the core.)

---

### Task 3: Move dependencies into `pyproject.toml`

**Files:** Modify `pyproject.toml`, `requirements.txt`; delete `shared/auth.py`

- [ ] **Step 1: `pyproject.toml`**

Replace

```toml
# Dependencies are maintained in requirements.txt — single source of truth.
dynamic = ["dependencies"]
```

with

```toml
# Core: what the decision pipeline, the audit chain and the CLIs import.
# Lower bounds only, so installing Kyvern never downgrades your packages.
dependencies = [
    "cryptography>=43",          # Ed25519 signing; rfc3161-client needs >=43
    "pydantic>=2.9,<3",
    "pyyaml>=6.0",
    "filelock>=3.12",            # inter-process lock for appending to the audit chain
    "rfc3161-client>=1.0.9",     # RFC 3161 anchoring; <1.0.3 had CVE-2025-52556
    "certifi",                   # trusted roots for verifying TSA timestamps
    "reportlab>=4.0",            # kyvern-report PDF
    "httpx>=0.27,<1",            # LLM client
]
```

delete the table

```toml
[tool.setuptools.dynamic]
dependencies = { file = ["requirements.txt"] }
```

replace the `dev` extra with

```toml
dev = [
    "pytest>=7.4.0",
    "pytest-asyncio>=0.23.0",
    "pytest-cov>=4.1.0",
    "ruff>=0.4.0",
    "mypy>=1.10.0",
    "pypdf>=4.0.0",   # PDF assertions in the report tests
]
```

and add after the `dev` extra:

```toml
fusion = [
    # Multi-sensor tracking and the detector services: pip install -e ".[fusion]"
    # Camera/RF hardware stacks (ultralytics, opencv, scapy, bleak, mavsdk) are
    # imported lazily and installed separately when those services run.
    "numpy>=1.24",
    "scipy>=1.11",
    "filterpy>=1.4.5,<2",
    "pyproj>=3.6",               # optional: shared/geo.py falls back to flat-Earth math
    "nats-py>=2.6,<3",
    "prometheus-client>=0.19",
]
```

- [ ] **Step 2: `requirements.txt`**

Replace the whole file with:

```
# Full development environment (all extras): pip install -r requirements.txt
# To use Kyvern: pip install .   (add ".[mcp]", ".[llm]" or ".[fusion]" as needed)
-e .[dev,fusion,llm,mcp]
```

- [ ] **Step 3: Delete the dead module**

Run: `git rm shared/auth.py`, then `git grep -n "shared.auth\|from shared import auth"` → no output.

- [ ] **Step 4: Reinstall and run everything**

```powershell
python -m pip install -e . --no-deps -q --disable-pip-version-check
python -m pytest -q -p no:cacheprovider
python -m ruff check .
```

Expected: `283 passed, 4 skipped`; `All checks passed!` (all extras are already installed on the dev machine).

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml requirements.txt scripts/smoke_core_install.py
git commit -m "build: light core dependencies in pyproject, sensor fusion as an extra

Drops packages the code never imports (fastapi, uvicorn, pydantic-settings,
sqlalchemy, alembic, PyJWT, passlib, python-multipart, python-dotenv,
scikit-learn, joblib, opentelemetry x3) and the dead shared/auth.py. pydantic is
no longer pinned to 2.9.2, so installing Kyvern does not downgrade it.
requirements.txt is now a one-line full-dev environment."
```

(`git rm` already staged the deletion.)

---

### Task 4: Prove the core install locally

- [ ] **Step 1: Count after, and run the smoke script in a core-only venv**

```powershell
$sp = "<scratchpad>"
& "$sp\venv-count\Scripts\python.exe" -m pip install -q --disable-pip-version-check --dry-run --ignore-installed --report "$sp\deps-after.json" .
python -c "import json; r=json.load(open(r'$sp\deps-after.json', encoding='utf-8')); names=sorted(i['metadata']['name'] for i in r['install']); print(len(names)); print(', '.join(names))"

python -m venv "$sp\venv-core"
& "$sp\venv-core\Scripts\python.exe" -m pip install -q --disable-pip-version-check .
Push-Location $sp
& "$sp\venv-core\Scripts\python.exe" "<repo>\scripts\smoke_core_install.py"; "smoke-exit=$LASTEXITCODE"
Pop-Location
```

Expected: the after-count is well below the before-count (under twenty); `core install OK`, `smoke-exit=0`.

- [ ] **Step 2: Re-run the import scan**

```bash
python - <<'EOF'
import ast, sys, pathlib, collections
first_party = {"cli", "kyvern", "services", "shared", "tests", "scripts", "examples", "config"}
declared = {"cryptography", "pydantic", "yaml", "filelock", "rfc3161_client", "certifi", "reportlab", "httpx",
            "langgraph", "anthropic", "mcp", "numpy", "scipy", "filterpy", "pyproj", "nats", "prometheus_client",
            "pytest", "pypdf", "colorama"}
lazy_hardware = {"cv2", "faiss", "ultralytics", "scapy", "bleak", "mavsdk", "rclpy", "std_msgs"}
undeclared = collections.defaultdict(set)
for path in pathlib.Path(".").rglob("*.py"):
    if path.parts[0] in {".git", "site", "build"} or "__pycache__" in path.parts or "egg-info" in str(path):
        continue
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8-sig"))):
        mods = [a.name for a in node.names] if isinstance(node, ast.Import) else (
            [node.module] if isinstance(node, ast.ImportFrom) and node.module and node.level == 0 else [])
        for m in mods:
            top = m.split(".")[0]
            if top not in sys.stdlib_module_names | first_party | declared | lazy_hardware | {"__future__"}:
                undeclared[top].add(str(path))
print(dict(undeclared) or "no undeclared imports")
EOF
```

Expected: `no undeclared imports`.

- [ ] **Step 3: Clean up**

Delete `<scratchpad>\venv-count`, `<scratchpad>\venv-core` (literal paths). Keep the two JSON reports for the PR text.

---

### Task 5: CI

**Files:** Modify `.github/workflows/ci.yml`

- [ ] **Step 1: Install all extras in the test job**

Change `run: pip install -e ".[dev,llm,mcp]"` to `run: pip install -e ".[dev,fusion,llm,mcp]"`.

- [ ] **Step 2: Add the core job** at the end of the file:

```yaml
  core-install:
    name: Core install (no extras)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install the core only
        run: |
          python -m venv /tmp/core
          /tmp/core/bin/pip install .

      - name: Smoke test from outside the checkout
        working-directory: /tmp
        run: /tmp/core/bin/python "$GITHUB_WORKSPACE/scripts/smoke_core_install.py"
```

- [ ] **Step 3: Validate and commit**

Run: `python -c "import yaml; d=yaml.safe_load(open('.github/workflows/ci.yml', encoding='utf-8')); print(list(d['jobs']))"` → `['test', 'core-install']`.

```bash
git add .github/workflows/ci.yml
git commit -m "ci: test with all extras and prove the core installs and runs without them"
```

---

### Task 6: Docs

**Files:** `README.md`, `CHANGELOG.md`

- [ ] **Step 1: README "Quick start"** — replace the code block under `## Quick start` with:

````markdown
Kyvern is not on PyPI yet; install from a clone of this repository.

```bash
pip install .                 # core: decisions, audit chain, kyvern-verify/report/anchor
pip install ".[mcp]"          # + kyvern-mcp (Claude Desktop)
pip install ".[llm]"          # + LLM advisor (LangGraph, Anthropic)
pip install ".[fusion]"       # + multi-sensor tracking and detector services
pip install -r requirements.txt && pytest   # full development environment
```
````

- [ ] **Step 2: CHANGELOG `[Unreleased]`** — add:

```markdown
### Changed
- Dependencies are declared in `pyproject.toml`: a light core (cryptography,
  pydantic, pyyaml, filelock, rfc3161-client, certifi, reportlab, httpx) plus
  extras `fusion`, `llm`, `mcp`, `dev`, `docs`. `pydantic` is no longer pinned
  to 2.9.2 and `numpy` is no longer capped below 2. `requirements.txt` installs
  the full development environment

### Removed
- Unused dependencies: fastapi, uvicorn, pydantic-settings, sqlalchemy,
  alembic, PyJWT, passlib, python-multipart, python-dotenv, scikit-learn,
  joblib, opentelemetry-sdk, opentelemetry-exporter-otlp-proto-grpc,
  opentelemetry-instrumentation-fastapi
- `shared/auth.py` (JWT helpers from the private deployment's web API; unused)
```

- [ ] **Step 3: Commit**

```bash
git add README.md CHANGELOG.md
git commit -m "docs: install the core or extras; changelog for the dependency cleanup"
```

---

### Task 7: Push and PR

- [ ] **Step 1:** `python -m pytest -q -p no:cacheprovider` → `283 passed, 4 skipped`; `python -m ruff check .` clean.
- [ ] **Step 2:** `git push -u origin chore/slim-deps`; `gh pr create --repo altunbulakemre75/kyvern --base main --head chore/slim-deps --title "Light core install: dependencies in pyproject, fusion as an extra" --body-file <scratchpad>/pr_slim_body.md` with: the before/after package counts and lists from Task 1/4, the removed packages, the new CI job, test plan, and `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.
- [ ] **Step 3:** Report the PR and CI result; merge only with the user's go-ahead.
