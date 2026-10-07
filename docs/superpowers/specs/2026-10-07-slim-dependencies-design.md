# Slim Dependencies: a Light Core Install with Extras

**Date:** 2026-10-07
**Status:** Approved in conversation
**Scope:** Move dependencies from `requirements.txt` into `pyproject.toml` as a small core plus extras; drop packages the code never imports; delete the dead `shared/auth.py`; add a CI job proving the core works without extras.
**Out of scope:** Moving the counter-UAS heritage modules (detectors, intercept planner, MAVSDK) out of the repository — a separate decision before the ROS2 demo; publishing to PyPI.

---

## 1. Problem

`pyproject.toml` reads its dependencies from `requirements.txt`, which still carries the private deployment's stack. A pilot running `pip install .` gets a web framework, an ORM, migrations, password hashing, OpenTelemetry (with `grpcio`), scikit-learn and the sensor-fusion stack — none of which the decision/audit core imports — and `pydantic==2.9.2`, which downgrades the user's own pydantic (it also forced `mcp` 1.12 and broke CI in October).

Third-party imports by area (AST scan, 2026-10-07):

| Area | Imports |
|---|---|
| Core: `services/decision`, `kyvern/`, `cli/`, `shared/paths.py`, `shared/schemas.py`, `services/autonomy/geofence.py` | cryptography, pydantic, yaml, filelock, rfc3161_client, certifi, reportlab, httpx (top-level in `llm_client.py`); `anthropic`, `langgraph` lazily; `colorama` optionally |
| Fusion and detector services | numpy, scipy, filterpy, pyproj (optional fallback), nats, prometheus_client; cv2, faiss, ultralytics, scapy, bleak, mavsdk (lazy, never pinned) |
| `shared/auth.py` | jwt — the module is imported nowhere |
| Nowhere | fastapi, uvicorn, pydantic-settings, sqlalchemy, alembic, passlib, python-multipart, python-dotenv, scikit-learn, joblib, opentelemetry-sdk, opentelemetry-exporter-otlp-proto-grpc, opentelemetry-instrumentation-fastapi |

## 2. Design

### 2.1 `pyproject.toml`

Remove `dynamic = ["dependencies"]` and the `[tool.setuptools.dynamic]` table; declare:

```toml
dependencies = [
    "cryptography>=43",          # Ed25519 signing; rfc3161-client needs >=43
    "pydantic>=2.9,<3",
    "pyyaml>=6.0",
    "filelock>=3.12",
    "rfc3161-client>=1.0.9",     # <1.0.3 had CVE-2025-52556
    "certifi",
    "reportlab>=4.0",
    "httpx>=0.27,<1",
]
```

Extras (`llm`, `mcp`, `docs` unchanged in content):

```toml
fusion = [   # multi-sensor tracking and the detector services
    "numpy>=1.24",
    "scipy>=1.11",
    "filterpy>=1.4.5,<2",
    "pyproj>=3.6",
    "nats-py>=2.6,<3",
    "prometheus-client>=0.19",
]
dev = [
    "pytest>=7.4", "pytest-asyncio>=0.23", "pytest-cov>=4.1",
    "ruff>=0.4", "mypy>=1.10", "pypdf>=4.0",
]
```

Lower bounds only (plus major-version caps where a major release is known to break), so installing Kyvern never downgrades a user's packages. `numpy<2` is dropped: the suite passes with numpy 2.4.

### 2.2 `requirements.txt`

Becomes a one-line convenience for a full development environment, so the README's `pip install -r requirements.txt` + `pytest` still works:

```
# Full development environment (all extras). Users: pip install .  or  ".[mcp]", ".[llm]", ".[fusion]"
-e .[dev,fusion,llm,mcp]
```

### 2.3 Dead code

Delete `shared/auth.py` (JWT helpers from the private deployment's web API; imported nowhere).

### 2.4 CI

- Test job: `pip install -e ".[dev,fusion,llm,mcp]"` (adds `fusion`, which the fusion tests need now that it is no longer in the core).
- New job **Core install (no extras)**, Python 3.12: in a fresh venv `pip install .`, then from a directory outside the checkout run `scripts/smoke_core_install.py`, which imports the decision pipeline and the CLIs, runs `decide_full()` for one track into a temporary chain, verifies it with `verify_chain`, and runs `kyvern-verify --help`, `kyvern-report --help`, `kyvern-anchor --help`. It fails if any import needs an extra.

### 2.5 Docs

- README "Quick start": core install `pip install .`, extras table (`mcp`, `llm`, `fusion`, `dev`), full dev env `pip install -r requirements.txt`.
- CHANGELOG `[Unreleased]` → Changed / Removed.

## 3. Acceptance criteria

- `pip install --dry-run --ignore-installed --report` in a fresh venv: the number of packages for `pip install .` before and after this change is recorded in the PR (expected: from dozens to under twenty).
- `scripts/smoke_core_install.py` passes in a fresh venv with only `pip install .`.
- Full suite passes with all extras; `ruff check .` clean; CI green, including the new core job.
- No remaining import of a package that is in neither the core nor an extra (re-run the AST scan; lazily imported optional hardware/vision packages excepted).
