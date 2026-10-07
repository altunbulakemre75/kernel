# Move the Counter-UAS Code to a Private Repository

**Date:** 2026-10-07
**Status:** Approved in conversation
**Context:** Positioning decision of 2026-10-07 — Kyvern is pitched to robotics teams as an audit layer for their own decision stack.
**Scope:** Move sensor adapters, multi-sensor tracking and counter-UAS autonomy out of `kyvern` into a new private repository `altunbulakemre75/kyvern-uas`; keep `kyvern` working and documented without them.
**Out of scope:** Rewriting git history (the code stays in `kyvern`'s public history); renaming the example decision engine's vocabulary; the decision-recording API and the README/docs narrative (next pieces); the ROS2 demo.

## 1. What moves

| Path | Content | Used by the core? |
|---|---|---|
| `services/detectors/` | camera (YOLO, calibration), RF/ODID, Wi-Fi OUI adapters | no |
| `services/autonomy/` | intercept planner, MAVSDK sender, geofence, waypoint schemas | only `geofence.haversine_m` (guardrails) |
| `services/fusion/` | Kalman/IMM tracking, association, NATS fusion service, drone catalog | no |
| `services/schemas/` | `Measurement`, `Track`, camera and RF event models | no |
| `shared/clock.py`, `geo.py`, `rate_limit.py`, `lifecycle.py` | helpers used only by the code above | no |
| `shared/heartbeat.py`, `logging_setup.py`, `utils.py` | imported nowhere | no |
| `tests/fusion/` (37 tests) and the sensor fixtures in `tests/conftest.py` | | — |

None of the moved code imports anything that stays in `kyvern`, so the cut is clean.

## 2. `kyvern-uas`

- Private repository under the user's account, created by Claude with `gh repo create --private`.
- Same paths as in `kyvern`, plus `services/__init__.py`, `shared/__init__.py`, `tests/__init__.py`, a `tests/conftest.py` with the moved fixtures, a `pyproject.toml` (pydantic, numpy, scipy, filterpy, pyproj, nats-py, prometheus-client; dev: pytest, pytest-asyncio) and a README stating the origin.
- One initial commit: `Import counter-UAS modules from kyvern@<sha>`, where `<sha>` is the `kyvern` commit the files were copied from.
- Its 37 tests pass.

## 3. `kyvern` after the move

- `haversine_m` moves into `services/decision/guardrails.py` (the only core use), with a direct unit test.
- The moved paths are deleted; `tests/conftest.py` keeps only decision fixtures and `isolated_home`.
- The `fusion` extra is removed; `requirements.txt`, the CI install line and the README install block drop it.
- `docs/architecture.md`: sections 2.2–2.5 become one short "What is not in this repository" section plus an accurate `shared/` table; the sensor and fusion steps of the data flow become one "Input" step; the sensor-adapter and observability subsections of §7 go; the ROS2 entry under action sinks describes the existing bridge; the directory map matches the tree.
- CHANGELOG `[Unreleased]` → Removed.

## 4. Acceptance

- `kyvern`: 247 passed (283 − 37 moved + 1 new), 4 skipped; `ruff check .` clean; the AST import scan finds nothing undeclared; `git grep` finds no import of a moved module; CI green including the core-install job.
- `kyvern-uas`: 37 passed; the GitHub repository is private.
