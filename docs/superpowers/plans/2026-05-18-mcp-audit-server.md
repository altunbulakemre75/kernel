# kernel-mcp Audit Query Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a read-only MCP server (`kernel-mcp`) that exposes the kernel decision-audit chain to Claude Desktop and other MCP clients over stdio, with signature verification surfaced on every event.

**Architecture:** Single source of truth = `chain.jsonl`. An `AuditChainStore` loads it into memory and exposes filter/get/search/verify helpers with debounced mtime hot-reload. `kernel.mcp.server.run()` uses the FastMCP SDK (`mcp.server.fastmcp.FastMCP`) to register 5 tools and 4 resources, all delegating to the store. The MCP SDK is an optional extra (`pip install kernel[mcp]`).

**Tech Stack:** Python 3.10+, `mcp>=1.0.0` (optional extra), Pydantic v2, existing `services.decision.audit_chain` + `policy_loader`, no new persistence layer.

**Spec:** [`docs/superpowers/specs/2026-05-18-mcp-audit-server-design.md`](../specs/2026-05-18-mcp-audit-server-design.md)

---

## File Map

| File | Action | Purpose |
|---|---|---|
| `kernel/audit/__init__.py` | Create | Package marker; re-exports `AuditChainStore`, `ChainVerifyResult`, `SearchHit`. |
| `kernel/audit/store.py` | Create | `AuditChainStore` + result dataclasses. |
| `kernel/mcp/__init__.py` | Create | SDK guard + public API re-exports. |
| `kernel/mcp/errors.py` | Create | `KernelMCPError` exception class. |
| `kernel/mcp/schemas.py` | Create | Pydantic I/O models. |
| `kernel/mcp/tools.py` | Create | `register_tools(app, store, policy_path)`. |
| `kernel/mcp/resources.py` | Create | `register_resources(app, store, policy_path)`. |
| `kernel/mcp/server.py` | Create | CLI argparse + `run()` entry. |
| `tests/audit/__init__.py` | Create | Package marker. |
| `tests/audit/conftest.py` | Create | `signing_keypair`, `sample_chain_file`, `tampered_chain_file` fixtures. |
| `tests/audit/test_store.py` | Create | Store unit tests. |
| `tests/mcp/__init__.py` | Create | Package marker. |
| `tests/mcp/conftest.py` | Create | Re-exports audit fixtures + `mcp_app` fixture. |
| `tests/mcp/test_server.py` | Create | `test_server_starts`, `test_chain_file_missing`. |
| `tests/mcp/test_tools.py` | Create | One test per tool + `test_invalid_inputs`. |
| `tests/mcp/test_resources.py` | Create | All 4 resources schema-stable. |
| `tests/mcp/test_integration.py` | Create | Env-gated real-MCP-client handshake. |
| `examples/mcp_claude_desktop_config.json` | Create | Copy-paste config block. |
| `docs/integrations/mcp.md` | Create | 30-second setup + tool reference. |
| `docs/roadmap.md` | Create | New file (does not exist yet) — indexing-at-100K note. |
| `pyproject.toml` | Modify | Add `[mcp]` extra, `kernel-mcp` console script. |

---

## Task 1: Bootstrap packages + pyproject + SDK guard

**Files:**
- Create: `kernel/audit/__init__.py`, `kernel/mcp/__init__.py`, `kernel/mcp/errors.py`
- Create: `tests/audit/__init__.py`, `tests/mcp/__init__.py`
- Modify: `pyproject.toml`

- [ ] **Step 1: Create empty package markers**

```bash
mkdir -p kernel/audit kernel/mcp tests/audit tests/mcp
touch kernel/audit/__init__.py tests/audit/__init__.py tests/mcp/__init__.py
```

- [ ] **Step 2: Write `kernel/mcp/errors.py`**

```python
class KernelMCPError(Exception):
    """Raised for kernel-mcp tool/resource handler errors.

    FastMCP surfaces the message in the JSON-RPC error response.
    """
```

- [ ] **Step 3: Write `kernel/mcp/__init__.py` with SDK guard**

```python
try:
    import mcp  # noqa: F401
except ImportError as exc:
    raise ImportError(
        "kernel.mcp requires the 'mcp' extra.\n"
        "Install with: pip install kernel[mcp]"
    ) from exc

from kernel.mcp.errors import KernelMCPError

__all__ = ["KernelMCPError"]
```

- [ ] **Step 4: Update `pyproject.toml` — add `[mcp]` extra and console script**

In `[project.optional-dependencies]` after the existing `llm` group, append:

```toml
mcp = [
    "mcp>=1.0.0",
]
```

In `[project.scripts]` after `kernel-report = ...`, append:

```toml
kernel-mcp = "kernel.mcp.server:run"
```

- [ ] **Step 5: Verify imports**

```bash
python -c "import kernel.audit; import kernel.mcp; print('ok')"
```
Expected: `ok` (if `mcp` SDK is installed) — or the documented `ImportError` if not.

- [ ] **Step 6: Commit**

```bash
git add kernel/audit/__init__.py kernel/mcp/__init__.py kernel/mcp/errors.py \
        tests/audit/__init__.py tests/mcp/__init__.py pyproject.toml
git commit -m "Bootstrap kernel.audit + kernel.mcp packages, add [mcp] extra"
```

---

## Task 2: AuditChainStore — load + filter (TDD)

**Files:**
- Create: `kernel/audit/store.py`
- Create: `tests/audit/conftest.py`
- Create: `tests/audit/test_store.py`

- [ ] **Step 1: Write `tests/audit/conftest.py` — shared fixtures**

```python
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from services.decision.audit_chain import sign_decision

_BASE_TS = datetime(2026, 5, 18, 14, 32, 0, tzinfo=timezone.utc)


@pytest.fixture
def signing_keypair(tmp_path: Path):
    sk = ed25519.Ed25519PrivateKey.generate()
    pub_path = tmp_path / "signing.pub"
    pub_path.write_bytes(
        sk.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return sk, sk.public_key(), pub_path


def _raw_events() -> list[dict]:
    return [
        {
            "chain_index": 0,
            "timestamp_iso": _BASE_TS.isoformat(),
            "action": "allow",
            "threat_level": "low",
            "policy_version_id": "p_test",
            "metadata": {"target": {"ip": "10.0.0.5"}, "rule_id": "r_001"},
        },
        {
            "chain_index": 1,
            "timestamp_iso": (_BASE_TS + timedelta(seconds=10)).isoformat(),
            "action": "block",
            "threat_level": "high",
            "policy_version_id": "p_test",
            "metadata": {"target": {"ip": "10.0.0.6"}, "rule_id": "r_002"},
        },
        {
            "chain_index": 2,
            "timestamp_iso": (_BASE_TS + timedelta(hours=2)).isoformat(),
            "action": "flag",
            "threat_level": "medium",
            "policy_version_id": "p_test",
            "metadata": {"target": {"ip": "10.0.0.7"}, "rule_id": "r_003"},
        },
        {
            "chain_index": 3,
            "timestamp_iso": (_BASE_TS + timedelta(days=2)).isoformat(),
            "action": "allow",
            "threat_level": "low",
            "policy_version_id": "p_test",
            "metadata": {"target": {"ip": "10.0.0.8"}, "rule_id": "r_001"},
        },
    ]


def _write_chain(path: Path, events: list[dict], sk) -> None:
    lines = []
    prev_hash = None
    for ev in events:
        signed = sign_decision(ev, prev_hash=prev_hash, signing_key=sk)
        lines.append(json.dumps(signed))
        prev_hash = signed["payload_hash"]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


@pytest.fixture
def sample_chain_file(tmp_path: Path, signing_keypair) -> Path:
    sk, _, _ = signing_keypair
    chain_file = tmp_path / "chain.jsonl"
    _write_chain(chain_file, _raw_events(), sk)
    return chain_file


@pytest.fixture
def tampered_chain_file(tmp_path: Path, signing_keypair) -> Path:
    """Chain where event[1].action was flipped after signing — breaks chain."""
    sk, _, _ = signing_keypair
    chain_file = tmp_path / "chain_tampered.jsonl"
    _write_chain(chain_file, _raw_events(), sk)
    raw = chain_file.read_text(encoding="utf-8").splitlines()
    ev1 = json.loads(raw[1])
    ev1["action"] = "allow"  # tamper — signature now invalid
    raw[1] = json.dumps(ev1)
    chain_file.write_text("\n".join(raw) + "\n", encoding="utf-8")
    return chain_file
```

- [ ] **Step 2: Write the failing tests for load + filter**

In `tests/audit/test_store.py`:

```python
from datetime import datetime, timezone, timedelta

from kernel.audit.store import AuditChainStore


def test_store_loads_jsonl(sample_chain_file):
    store = AuditChainStore(sample_chain_file, verify_on_query=False)
    store.load()
    assert len(store.events()) == 4
    assert store.events()[0]["action"] == "allow"


def test_filter_by_action(sample_chain_file):
    store = AuditChainStore(sample_chain_file, verify_on_query=False)
    store.load()
    blocks = store.filter(action="block")
    assert len(blocks) == 1
    assert blocks[0]["chain_index"] == 1


def test_filter_by_threat_level(sample_chain_file):
    store = AuditChainStore(sample_chain_file, verify_on_query=False)
    store.load()
    highs = store.filter(threat_level="high")
    assert len(highs) == 1
    assert highs[0]["chain_index"] == 1


def test_filter_by_time_window(sample_chain_file):
    store = AuditChainStore(sample_chain_file, verify_on_query=False)
    store.load()
    start = datetime(2026, 5, 18, 14, 32, 0, tzinfo=timezone.utc)
    end = start + timedelta(minutes=5)
    inside = store.filter(start_time=start, end_time=end)
    assert {e["chain_index"] for e in inside} == {0, 1}


def test_filter_limit_returns_newest_first(sample_chain_file):
    store = AuditChainStore(sample_chain_file, verify_on_query=False)
    store.load()
    last_two = store.filter(limit=2)
    assert [e["chain_index"] for e in last_two] == [3, 2]


def test_get_event_by_id(sample_chain_file):
    store = AuditChainStore(sample_chain_file, verify_on_query=False)
    store.load()
    ev = store.get(2)
    assert ev is not None
    assert ev["action"] == "flag"


def test_get_event_unknown_id_returns_none(sample_chain_file):
    store = AuditChainStore(sample_chain_file, verify_on_query=False)
    store.load()
    assert store.get(999) is None
```

- [ ] **Step 3: Run tests — verify they fail**

```bash
python -m pytest tests/audit/test_store.py -v 2>&1 | head -20
```
Expected: `ModuleNotFoundError: No module named 'kernel.audit.store'` or import error.

- [ ] **Step 4: Implement `kernel/audit/store.py` (load + filter only — verify in next task)**

```python
"""AuditChainStore — JSONL-backed read-only store for kernel decision audit chains."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class SearchHit:
    event_id: int
    timestamp_iso: str
    action: str
    sig_valid: bool | None
    snippet: str


@dataclass
class ChainVerifyResult:
    verified_count: int
    total_count: int
    first_break: dict | None
    integrity: str  # "OK" | "BROKEN" | "UNKNOWN"


class AuditChainStore:
    def __init__(
        self,
        chain_file: Path,
        public_key_path: Path | None = None,
        verify_on_query: bool = True,
        reload_debounce_seconds: float = 1.0,
    ) -> None:
        self._chain_file = Path(chain_file)
        self._public_key_path = Path(public_key_path) if public_key_path else None
        self._verify_on_query = verify_on_query
        self._reload_debounce = reload_debounce_seconds
        self._events: list[dict] = []
        self._mtime: float | None = None
        self._last_check_monotonic: float = 0.0
        self._public_key = None
        if self._public_key_path is not None:
            self._public_key = self._load_public_key(self._public_key_path)

    @staticmethod
    def _load_public_key(path: Path):
        from cryptography.hazmat.primitives import serialization
        return serialization.load_pem_public_key(path.read_bytes())

    def load(self) -> None:
        if not self._chain_file.exists():
            from kernel.mcp.errors import KernelMCPError
            raise KernelMCPError(f"chain file not found at {self._chain_file}")
        self._events = [
            json.loads(line)
            for line in self._chain_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self._mtime = self._chain_file.stat().st_mtime
        self._last_check_monotonic = time.monotonic()

    def reload_if_stale(self) -> None:
        now = time.monotonic()
        if now - self._last_check_monotonic < self._reload_debounce:
            return
        self._last_check_monotonic = now
        try:
            current_mtime = self._chain_file.stat().st_mtime
        except FileNotFoundError:
            from kernel.mcp.errors import KernelMCPError
            raise KernelMCPError(f"chain file not found at {self._chain_file}")
        if self._mtime is None or current_mtime != self._mtime:
            self.load()

    def events(self) -> list[dict]:
        return list(self._events)

    def get(self, event_id: int) -> dict | None:
        for ev in self._events:
            if ev.get("chain_index") == event_id:
                return ev
        return None

    def filter(
        self,
        *,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        action: str | None = None,
        threat_level: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        results = []
        for ev in self._events:
            if action is not None and ev.get("action") != action:
                continue
            if threat_level is not None and ev.get("threat_level") != threat_level:
                continue
            ts = ev.get("timestamp_iso")
            if start_time is not None and ts is not None:
                if datetime.fromisoformat(ts.replace("Z", "+00:00")) < start_time:
                    continue
            if end_time is not None and ts is not None:
                if datetime.fromisoformat(ts.replace("Z", "+00:00")) > end_time:
                    continue
            results.append(ev)
        results.sort(key=lambda e: e.get("chain_index", 0), reverse=True)
        return results[:limit]
```

- [ ] **Step 5: Run tests — verify they pass**

```bash
python -m pytest tests/audit/test_store.py -v
```
Expected: 7 passed.

- [ ] **Step 6: Commit**

```bash
git add kernel/audit/store.py tests/audit/conftest.py tests/audit/test_store.py
git commit -m "Add AuditChainStore: JSONL load + time/action/threat filters"
```

---

## Task 3: AuditChainStore — verify helpers + debounced reload

**Files:**
- Modify: `kernel/audit/store.py`
- Modify: `tests/audit/test_store.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/audit/test_store.py`:

```python
import time

import pytest


def test_verify_event_clean(sample_chain_file, signing_keypair):
    _, _, pub_path = signing_keypair
    store = AuditChainStore(sample_chain_file, public_key_path=pub_path)
    store.load()
    assert store.verify_event(0) is True
    assert store.verify_event(2) is True


def test_verify_event_tampered(tampered_chain_file, signing_keypair):
    _, _, pub_path = signing_keypair
    store = AuditChainStore(tampered_chain_file, public_key_path=pub_path)
    store.load()
    assert store.verify_event(1) is False


def test_verify_event_without_key_returns_none(sample_chain_file):
    store = AuditChainStore(sample_chain_file, verify_on_query=False)
    store.load()
    assert store.verify_event(0) is None


def test_verify_chain_range_clean(sample_chain_file, signing_keypair):
    _, _, pub_path = signing_keypair
    store = AuditChainStore(sample_chain_file, public_key_path=pub_path)
    store.load()
    result = store.verify_chain_range(0, None)
    assert result.integrity == "OK"
    assert result.verified_count == 4
    assert result.first_break is None


def test_verify_chain_range_tampered(tampered_chain_file, signing_keypair):
    _, _, pub_path = signing_keypair
    store = AuditChainStore(tampered_chain_file, public_key_path=pub_path)
    store.load()
    result = store.verify_chain_range(0, None)
    assert result.integrity == "BROKEN"
    assert result.first_break is not None
    assert result.first_break["id"] == 1


def test_verify_chain_range_without_key_unknown(sample_chain_file):
    store = AuditChainStore(sample_chain_file, verify_on_query=False)
    store.load()
    result = store.verify_chain_range(0, None)
    assert result.integrity == "UNKNOWN"


def test_reload_debounce_skips_within_window(sample_chain_file):
    store = AuditChainStore(
        sample_chain_file, verify_on_query=False, reload_debounce_seconds=10.0
    )
    store.load()
    initial_mtime = store._mtime
    # Append a new event by hand
    sample_chain_file.write_text(
        sample_chain_file.read_text(encoding="utf-8") + '{"chain_index": 99}\n',
        encoding="utf-8",
    )
    # Force a fresh mtime
    new_time = (initial_mtime or 0) + 100
    import os
    os.utime(sample_chain_file, (new_time, new_time))
    # Within debounce window — should NOT reload
    store.reload_if_stale()
    assert len(store.events()) == 4


def test_reload_debounce_picks_up_changes_after_window(sample_chain_file):
    store = AuditChainStore(
        sample_chain_file, verify_on_query=False, reload_debounce_seconds=0.05
    )
    store.load()
    initial_mtime = store._mtime
    sample_chain_file.write_text(
        sample_chain_file.read_text(encoding="utf-8")
        + '{"chain_index": 99, "action": "allow"}\n',
        encoding="utf-8",
    )
    import os
    os.utime(sample_chain_file, ((initial_mtime or 0) + 100, (initial_mtime or 0) + 100))
    time.sleep(0.1)
    store.reload_if_stale()
    assert len(store.events()) == 5
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
python -m pytest tests/audit/test_store.py -v 2>&1 | tail -30
```
Expected: 8 new tests fail with `AttributeError: 'AuditChainStore' object has no attribute 'verify_event'`.

- [ ] **Step 3: Implement verify_event + verify_chain_range**

Append to `kernel/audit/store.py`:

```python
    def verify_event(self, event_id: int) -> bool | None:
        if self._public_key is None or not self._verify_on_query:
            return None
        from services.decision.audit_chain import verify_decision
        ev = self.get(event_id)
        if ev is None:
            return None
        return verify_decision(ev, self._public_key)

    def verify_chain_range(
        self,
        start_id: int | None,
        end_id: int | None,
    ) -> ChainVerifyResult:
        if self._public_key is None or not self._verify_on_query:
            return ChainVerifyResult(
                verified_count=0,
                total_count=len(self._events),
                first_break=None,
                integrity="UNKNOWN",
            )
        from services.decision.audit_chain import verify_chain
        start = 0 if start_id is None else start_id
        end = self._events[-1].get("chain_index", 0) if self._events else 0
        if end_id is not None:
            end = end_id
        slice_events = [e for e in self._events if start <= e.get("chain_index", -1) <= end]
        ok, broken_idx = verify_chain(slice_events, self._public_key)
        if ok:
            return ChainVerifyResult(
                verified_count=len(slice_events),
                total_count=len(slice_events),
                first_break=None,
                integrity="OK",
            )
        broken_event = slice_events[broken_idx] if broken_idx is not None else None
        broken_id = broken_event.get("chain_index", broken_idx) if broken_event else None
        return ChainVerifyResult(
            verified_count=broken_idx or 0,
            total_count=len(slice_events),
            first_break={"id": broken_id, "reason": "signature_or_chain_link_invalid"},
            integrity="BROKEN",
        )
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/audit/test_store.py -v
```
Expected: 15 passed.

- [ ] **Step 5: Commit**

```bash
git add kernel/audit/store.py tests/audit/test_store.py
git commit -m "AuditChainStore: signature + chain verification, debounced hot-reload"
```

---

## Task 4: AuditChainStore — search with recursive flatten

**Files:**
- Modify: `kernel/audit/store.py`
- Modify: `tests/audit/test_store.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/audit/test_store.py`:

```python
def test_search_top_level_field(sample_chain_file):
    store = AuditChainStore(sample_chain_file, verify_on_query=False)
    store.load()
    hits = store.search("block")
    assert any(h.event_id == 1 for h in hits)


def test_search_nested_field(sample_chain_file):
    """Recursive flatten must find values in nested dicts."""
    store = AuditChainStore(sample_chain_file, verify_on_query=False)
    store.load()
    hits = store.search("10.0.0.7")
    assert any(h.event_id == 2 for h in hits)


def test_search_case_insensitive(sample_chain_file):
    store = AuditChainStore(sample_chain_file, verify_on_query=False)
    store.load()
    hits_lower = store.search("block")
    hits_upper = store.search("BLOCK")
    assert {h.event_id for h in hits_lower} == {h.event_id for h in hits_upper}


def test_search_limit(sample_chain_file):
    store = AuditChainStore(sample_chain_file, verify_on_query=False)
    store.load()
    hits = store.search("allow", limit=1)
    assert len(hits) == 1


def test_search_snippet_contains_query(sample_chain_file):
    store = AuditChainStore(sample_chain_file, verify_on_query=False)
    store.load()
    hits = store.search("10.0.0.7")
    assert "10.0.0.7" in hits[0].snippet
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
python -m pytest tests/audit/test_store.py::test_search_top_level_field -v 2>&1 | tail -10
```
Expected: `AttributeError: 'AuditChainStore' object has no attribute 'search'`.

- [ ] **Step 3: Implement `search` + `_flatten`**

Append to `kernel/audit/store.py`:

```python
def _flatten_value(obj: Any) -> str:
    if isinstance(obj, dict):
        return " ".join(_flatten_value(v) for v in obj.values())
    if isinstance(obj, (list, tuple, set)):
        return " ".join(_flatten_value(v) for v in obj)
    return str(obj)
```

And add this method to the `AuditChainStore` class:

```python
    def search(self, query: str, limit: int = 50) -> list[SearchHit]:
        q = query.lower()
        results: list[SearchHit] = []
        for ev in self._events:
            flat = _flatten_value(ev).lower()
            idx = flat.find(q)
            if idx == -1:
                continue
            half = 100
            start = max(0, idx - half)
            end = min(len(flat), idx + len(q) + half)
            snippet = flat[start:end]
            results.append(SearchHit(
                event_id=ev.get("chain_index", -1),
                timestamp_iso=ev.get("timestamp_iso", ""),
                action=ev.get("action", ""),
                sig_valid=self.verify_event(ev.get("chain_index", -1)),
                snippet=snippet,
            ))
            if len(results) >= limit:
                break
        return results
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/audit/test_store.py -v
```
Expected: 20 passed.

- [ ] **Step 5: Commit**

```bash
git add kernel/audit/store.py tests/audit/test_store.py
git commit -m "AuditChainStore: case-insensitive recursive-flatten search"
```

---

## Task 5: kernel.audit package exports + Pydantic schemas

**Files:**
- Modify: `kernel/audit/__init__.py`
- Create: `kernel/mcp/schemas.py`

- [ ] **Step 1: Write `kernel/audit/__init__.py`**

```python
from kernel.audit.store import AuditChainStore, ChainVerifyResult, SearchHit

__all__ = ["AuditChainStore", "ChainVerifyResult", "SearchHit"]
```

- [ ] **Step 2: Write `kernel/mcp/schemas.py`**

```python
"""Pydantic input/output models for kernel-mcp tools and resources."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


# ── Tool inputs ──────────────────────────────────────────────────────────────

class QueryEventsInput(BaseModel):
    start_time: str | None = None
    end_time: str | None = None
    action: Literal["allow", "block", "flag"] | None = None
    threat_level: Literal["low", "medium", "high"] | None = None
    limit: int = Field(default=100, ge=1, le=1000)


class GetEventInput(BaseModel):
    event_id: int


class GetStatsInput(BaseModel):
    window: Literal["1h", "24h", "7d", "30d", "all"] = "24h"


class VerifyChainInput(BaseModel):
    start_id: int | None = None
    end_id: int | None = None


class SearchEventsInput(BaseModel):
    query: str
    limit: int = Field(default=50, ge=1, le=500)


# ── Tool outputs ─────────────────────────────────────────────────────────────

class EventSummary(BaseModel):
    id: int
    timestamp_iso: str
    action: str
    threat_level: str | None = None
    sig_valid: bool | None = None


class EventDetail(BaseModel):
    event: dict[str, Any]
    sig_valid: bool | None = None
    chain_link: Literal["OK", "BROKEN", "UNKNOWN", "GENESIS"]


class ChainStatusSummary(BaseModel):
    verified: int
    total: int
    integrity: Literal["OK", "BROKEN", "UNKNOWN"]


class StatsResponse(BaseModel):
    action_distribution: dict[str, int]
    threat_distribution: dict[str, int]
    chain_status: ChainStatusSummary
    period: dict[str, str]


class VerifyChainResponse(BaseModel):
    verified_count: int
    total_count: int
    first_break: dict[str, Any] | None
    integrity: Literal["OK", "BROKEN", "UNKNOWN"]


class SearchHitOut(BaseModel):
    event_id: int
    timestamp_iso: str
    action: str
    sig_valid: bool | None
    snippet: str
```

- [ ] **Step 3: Verify imports**

```bash
python -c "from kernel.audit import AuditChainStore; from kernel.mcp.schemas import QueryEventsInput; print('ok')"
```
Expected: `ok`.

- [ ] **Step 4: Commit**

```bash
git add kernel/audit/__init__.py kernel/mcp/schemas.py
git commit -m "Add kernel.audit exports and kernel.mcp.schemas Pydantic I/O models"
```

---

## Task 6: kernel.mcp.tools — register 5 tool handlers (TDD)

**Files:**
- Create: `kernel/mcp/tools.py`
- Create: `tests/mcp/conftest.py`
- Create: `tests/mcp/test_tools.py`

- [ ] **Step 1: Write `tests/mcp/conftest.py`**

```python
"""Re-export audit fixtures so tests/mcp/ can use them."""
import pytest

from kernel.audit import AuditChainStore

# Re-export tests/audit fixtures
from tests.audit.conftest import (  # noqa: F401
    signing_keypair,
    sample_chain_file,
    tampered_chain_file,
)


@pytest.fixture
def store(sample_chain_file, signing_keypair):
    _, _, pub_path = signing_keypair
    s = AuditChainStore(sample_chain_file, public_key_path=pub_path)
    s.load()
    return s


@pytest.fixture
def store_unverified(sample_chain_file):
    s = AuditChainStore(sample_chain_file, verify_on_query=False)
    s.load()
    return s


@pytest.fixture
def store_tampered(tampered_chain_file, signing_keypair):
    _, _, pub_path = signing_keypair
    s = AuditChainStore(tampered_chain_file, public_key_path=pub_path)
    s.load()
    return s
```

- [ ] **Step 2: Write the failing tool tests**

In `tests/mcp/test_tools.py`:

```python
import pytest
from mcp.server.fastmcp import FastMCP

from kernel.mcp.errors import KernelMCPError
from kernel.mcp.tools import register_tools


def _make_app(store, policy_path=None):
    app = FastMCP("kernel-test")
    register_tools(app, store, policy_path=policy_path)
    return app


def _call_tool(app, name, **kwargs):
    """Invoke a registered FastMCP tool synchronously and return the result."""
    tool = app._tool_manager.get_tool(name)
    fn = tool.fn
    return fn(**kwargs)


def test_query_events_filter_by_action(store):
    app = _make_app(store)
    result = _call_tool(app, "query_events", action="block")
    assert len(result) == 1
    assert result[0]["action"] == "block"
    assert "sig_valid" in result[0]


def test_query_events_filter_by_threat_level(store):
    app = _make_app(store)
    result = _call_tool(app, "query_events", threat_level="high")
    assert len(result) == 1
    assert result[0]["threat_level"] == "high"


def test_query_events_filter_by_time_range(store):
    app = _make_app(store)
    result = _call_tool(
        app,
        "query_events",
        start_time="2026-05-18T14:32:00+00:00",
        end_time="2026-05-18T14:32:30+00:00",
    )
    assert {e["id"] for e in result} == {0, 1}


def test_query_events_invalid_time_format(store):
    app = _make_app(store)
    with pytest.raises(KernelMCPError, match="invalid time format"):
        _call_tool(app, "query_events", start_time="not-iso")


def test_query_events_limit_out_of_range(store):
    app = _make_app(store)
    with pytest.raises(KernelMCPError, match="limit must be between"):
        _call_tool(app, "query_events", limit=0)


def test_get_event_clean_signature(store):
    app = _make_app(store)
    result = _call_tool(app, "get_event", event_id=0)
    assert result["sig_valid"] is True
    assert result["chain_link"] == "GENESIS"


def test_get_event_tampered_signature(store_tampered):
    app = _make_app(store_tampered)
    result = _call_tool(app, "get_event", event_id=1)
    assert result["sig_valid"] is False


def test_get_event_sig_valid_null_when_verify_disabled(store_unverified):
    app = _make_app(store_unverified)
    result = _call_tool(app, "get_event", event_id=0)
    assert result["sig_valid"] is None
    assert result["chain_link"] == "UNKNOWN"


def test_get_event_unknown_id_returns_none(store):
    app = _make_app(store)
    result = _call_tool(app, "get_event", event_id=999)
    assert result is None


def test_get_stats_window_24h(store):
    app = _make_app(store)
    result = _call_tool(app, "get_stats", window="24h")
    # Fixture has 3 events on day 1 (allow, block, flag) plus 1 on day 3
    assert sum(result["action_distribution"].values()) == 3
    assert result["chain_status"]["integrity"] == "OK"


def test_get_stats_window_all(store):
    app = _make_app(store)
    result = _call_tool(app, "get_stats", window="all")
    assert sum(result["action_distribution"].values()) == 4


def test_get_stats_invalid_window(store):
    app = _make_app(store)
    with pytest.raises(Exception):  # Pydantic ValidationError wrapped
        _call_tool(app, "get_stats", window="not-a-window")


def test_verify_chain_clean(store):
    app = _make_app(store)
    result = _call_tool(app, "verify_chain")
    assert result["integrity"] == "OK"
    assert result["first_break"] is None


def test_verify_chain_tampered(store_tampered):
    app = _make_app(store_tampered)
    result = _call_tool(app, "verify_chain")
    assert result["integrity"] == "BROKEN"
    assert result["first_break"]["id"] == 1


def test_search_events_nested_field(store):
    app = _make_app(store)
    result = _call_tool(app, "search_events", query="10.0.0.7")
    assert len(result) >= 1
    assert any("10.0.0.7" in h["snippet"] for h in result)
```

- [ ] **Step 3: Run tests — verify they fail**

```bash
python -m pytest tests/mcp/test_tools.py -v 2>&1 | head -20
```
Expected: `ImportError: cannot import name 'register_tools' from 'kernel.mcp.tools'`.

- [ ] **Step 4: Implement `kernel/mcp/tools.py`**

```python
"""kernel.mcp.tools — register the 5 read-only tools on a FastMCP app."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP

from kernel.audit import AuditChainStore
from kernel.mcp.errors import KernelMCPError


def _parse_iso(value: str | None, field: str) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise KernelMCPError(
            f"invalid time format for '{field}' — expected ISO 8601, "
            f"e.g. 2026-05-18T14:32:07Z"
        ) from exc


def _summary(ev: dict, sig_valid: bool | None) -> dict:
    return {
        "id": ev.get("chain_index", -1),
        "timestamp_iso": ev.get("timestamp_iso", ""),
        "action": ev.get("action", ""),
        "threat_level": ev.get("threat_level"),
        "sig_valid": sig_valid,
    }


def _window_to_start(window: str, now: datetime) -> datetime | None:
    if window == "all":
        return None
    deltas = {
        "1h": timedelta(hours=1),
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
    }
    return now - deltas[window]


def register_tools(
    app: FastMCP,
    store: AuditChainStore,
    *,
    policy_path: Path | None = None,
) -> None:

    @app.tool(description="Query audit events with optional time, action, and threat filters.")
    def query_events(
        start_time: str | None = None,
        end_time: str | None = None,
        action: str | None = None,
        threat_level: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        if not (1 <= limit <= 1000):
            raise KernelMCPError("limit must be between 1 and 1000")
        store.reload_if_stale()
        events = store.filter(
            start_time=_parse_iso(start_time, "start_time"),
            end_time=_parse_iso(end_time, "end_time"),
            action=action,
            threat_level=threat_level,
            limit=limit,
        )
        return [
            _summary(ev, store.verify_event(ev.get("chain_index", -1)))
            for ev in events
        ]

    @app.tool(description="Fetch a single audit event by chain_index with signature + chain-link status.")
    def get_event(event_id: int) -> dict | None:
        store.reload_if_stale()
        ev = store.get(event_id)
        if ev is None:
            return None
        sig_valid = store.verify_event(event_id)
        if sig_valid is None:
            chain_link: str = "UNKNOWN"
        elif event_id == 0:
            chain_link = "GENESIS"
        else:
            prev = store.get(event_id - 1)
            chain_link = (
                "OK"
                if prev is not None
                and ev.get("prev_hash") == prev.get("payload_hash")
                else "BROKEN"
            )
        return {"event": ev, "sig_valid": sig_valid, "chain_link": chain_link}

    @app.tool(description="Aggregated stats for a time window (1h/24h/7d/30d/all).")
    def get_stats(window: str = "24h") -> dict:
        if window not in {"1h", "24h", "7d", "30d", "all"}:
            raise KernelMCPError(
                "window must be one of: 1h, 24h, 7d, 30d, all"
            )
        store.reload_if_stale()
        now = datetime.now(timezone.utc)
        start = _window_to_start(window, now)
        events = store.filter(start_time=start, limit=10_000)
        action_dist: dict[str, int] = {}
        threat_dist: dict[str, int] = {}
        for ev in events:
            action_dist[ev.get("action", "unknown")] = (
                action_dist.get(ev.get("action", "unknown"), 0) + 1
            )
            tl = ev.get("threat_level")
            if tl:
                threat_dist[tl] = threat_dist.get(tl, 0) + 1
        chain_result = store.verify_chain_range(None, None)
        return {
            "action_distribution": action_dist,
            "threat_distribution": threat_dist,
            "chain_status": {
                "verified": chain_result.verified_count,
                "total": chain_result.total_count,
                "integrity": chain_result.integrity,
            },
            "period": {
                "start": start.isoformat() if start else "",
                "end": now.isoformat(),
            },
        }

    @app.tool(description="Verify integrity of the audit chain (or a subrange).")
    def verify_chain(
        start_id: int | None = None,
        end_id: int | None = None,
    ) -> dict:
        store.reload_if_stale()
        result = store.verify_chain_range(start_id, end_id)
        return {
            "verified_count": result.verified_count,
            "total_count": result.total_count,
            "first_break": result.first_break,
            "integrity": result.integrity,
        }

    @app.tool(description="Case-insensitive substring search across all event fields (nested).")
    def search_events(query: str, limit: int = 50) -> list[dict]:
        if not (1 <= limit <= 500):
            raise KernelMCPError("limit must be between 1 and 500")
        store.reload_if_stale()
        hits = store.search(query, limit=limit)
        return [
            {
                "event_id": h.event_id,
                "timestamp_iso": h.timestamp_iso,
                "action": h.action,
                "sig_valid": h.sig_valid,
                "snippet": h.snippet,
            }
            for h in hits
        ]
```

- [ ] **Step 5: Run tests**

```bash
python -m pytest tests/mcp/test_tools.py -v
```
Expected: 15 passed.

- [ ] **Step 6: Commit**

```bash
git add kernel/mcp/tools.py tests/mcp/conftest.py tests/mcp/test_tools.py
git commit -m "Add kernel.mcp.tools: 5 read-only tool handlers with TDD coverage"
```

---

## Task 7: kernel.mcp.resources — register 4 resources

**Files:**
- Create: `kernel/mcp/resources.py`
- Create: `tests/mcp/test_resources.py`

- [ ] **Step 1: Write failing tests**

In `tests/mcp/test_resources.py`:

```python
import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from kernel.mcp.resources import register_resources


def _make_app(store, policy_path=None):
    app = FastMCP("kernel-test")
    register_resources(app, store, policy_path=policy_path)
    return app


def _resource_fn(app, uri):
    return app._resource_manager._resources[uri].fn


def test_resource_recent_returns_event_list(store):
    app = _make_app(store)
    payload = json.loads(_resource_fn(app, "kernel://audit/recent")())
    assert isinstance(payload, list)
    assert payload[0]["id"] in {0, 1, 2, 3}


def test_resource_today_has_stats_shape(store):
    app = _make_app(store)
    payload = json.loads(_resource_fn(app, "kernel://stats/today")())
    assert "action_distribution" in payload
    assert "threat_distribution" in payload
    assert "chain_status" in payload
    assert "period" in payload


def test_resource_chain_status_integrity(store):
    app = _make_app(store)
    payload = json.loads(_resource_fn(app, "kernel://chain/status")())
    assert payload["integrity"] == "OK"
    assert payload["chain_length"] == 4
    assert "chain_file" in payload


def test_resource_policy_active_metadata_only(store, tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "rules:\n  - rule_id: r_001\n    description: test\n    when_threat_level: low\n    requires_operator_approval: false\n    action: log\n",
        encoding="utf-8",
    )
    app = _make_app(store, policy_path=policy)
    payload = json.loads(_resource_fn(app, "kernel://policy/active")())
    assert "version_id" in payload
    assert "version_short" in payload
    assert "loaded_at" in payload
    assert "path" in payload
    # Critical: body NEVER exposed
    assert "rules" not in payload
    assert "raw_bytes" not in payload


def test_resource_policy_active_missing_file(store, tmp_path):
    app = _make_app(store, policy_path=tmp_path / "does-not-exist.yaml")
    payload = json.loads(_resource_fn(app, "kernel://policy/active")())
    assert "error" in payload
    assert "not found" in payload["error"]
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
python -m pytest tests/mcp/test_resources.py -v 2>&1 | head -10
```
Expected: `ImportError`.

- [ ] **Step 3: Implement `kernel/mcp/resources.py`**

```python
"""kernel.mcp.resources — register the 4 read-only resources on a FastMCP app."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from kernel.audit import AuditChainStore


def _today_bounds() -> tuple[datetime, datetime]:
    now = datetime.now().astimezone()
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    end = start.replace(hour=23, minute=59, second=59, microsecond=999_999)
    return start, end


def register_resources(
    app: FastMCP,
    store: AuditChainStore,
    *,
    policy_path: Path | None = None,
) -> None:

    @app.resource("kernel://audit/recent", description="Last 100 audit events.")
    def recent() -> str:
        store.reload_if_stale()
        events = store.filter(limit=100)
        payload = [
            {
                "id": ev.get("chain_index", -1),
                "timestamp_iso": ev.get("timestamp_iso", ""),
                "action": ev.get("action", ""),
                "threat_level": ev.get("threat_level"),
                "sig_valid": store.verify_event(ev.get("chain_index", -1)),
            }
            for ev in events
        ]
        return json.dumps(payload)

    @app.resource(
        "kernel://stats/today",
        description=(
            "Today's stats — server-host local-day boundaries (00:00–23:59:59 local TZ). "
            "Not a rolling 24-hour window."
        ),
    )
    def today() -> str:
        store.reload_if_stale()
        start, end = _today_bounds()
        events = store.filter(
            start_time=start.astimezone(timezone.utc),
            end_time=end.astimezone(timezone.utc),
            limit=10_000,
        )
        action_dist: dict[str, int] = {}
        threat_dist: dict[str, int] = {}
        for ev in events:
            action_dist[ev.get("action", "unknown")] = (
                action_dist.get(ev.get("action", "unknown"), 0) + 1
            )
            tl = ev.get("threat_level")
            if tl:
                threat_dist[tl] = threat_dist.get(tl, 0) + 1
        chain = store.verify_chain_range(None, None)
        payload = {
            "action_distribution": action_dist,
            "threat_distribution": threat_dist,
            "chain_status": {
                "verified": chain.verified_count,
                "total": chain.total_count,
                "integrity": chain.integrity,
            },
            "period": {
                "start": start.isoformat(),
                "end": end.isoformat(),
            },
        }
        return json.dumps(payload)

    @app.resource(
        "kernel://chain/status",
        description="Chain integrity verification result and chain length.",
    )
    def chain_status() -> str:
        store.reload_if_stale()
        chain = store.verify_chain_range(None, None)
        payload = {
            "verified_count": chain.verified_count,
            "total_count": chain.total_count,
            "first_break": chain.first_break,
            "integrity": chain.integrity,
            "chain_length": len(store.events()),
            "chain_file": str(store._chain_file),
        }
        return json.dumps(payload)

    @app.resource(
        "kernel://policy/active",
        description="Active policy metadata only — version_id, version_short, path, loaded_at. Body not exposed.",
    )
    def policy_active() -> str:
        if policy_path is None:
            return json.dumps({"error": "no policy configured — pass --policy"})
        if not Path(policy_path).exists():
            return json.dumps({"error": f"policy file not found at {policy_path}"})
        from services.decision.policy_loader import load_policy
        loaded = load_policy(str(policy_path))
        return json.dumps({
            "version_id": loaded.version_id,
            "version_short": loaded.version_short,
            "path": loaded.path,
            "loaded_at": loaded.loaded_at.isoformat(),
        })
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/mcp/test_resources.py -v
```
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add kernel/mcp/resources.py tests/mcp/test_resources.py
git commit -m "Add kernel.mcp.resources: 4 read-only resources (policy metadata only)"
```

---

## Task 8: kernel.mcp.server — CLI + stdio bootstrap

**Files:**
- Create: `kernel/mcp/server.py`
- Create: `tests/mcp/test_server.py`

- [ ] **Step 1: Write failing tests**

In `tests/mcp/test_server.py`:

```python
import pytest

from kernel.mcp.errors import KernelMCPError
from kernel.mcp.server import build_app, parse_args


def test_parse_args_defaults():
    ns = parse_args([])
    assert ns.chain_file.endswith("chain.jsonl")
    assert ns.pubkey.endswith("signing.pub")
    assert ns.verify_on_query is True


def test_parse_args_no_verify():
    ns = parse_args(["--no-verify-on-query"])
    assert ns.verify_on_query is False


def test_build_app_starts(sample_chain_file, signing_keypair, tmp_path):
    _, _, pub_path = signing_keypair
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "rules:\n  - rule_id: r_001\n    description: t\n    when_threat_level: low\n    requires_operator_approval: false\n    action: log\n",
        encoding="utf-8",
    )
    app = build_app(
        chain_file=sample_chain_file,
        pubkey=pub_path,
        policy=policy,
        verify_on_query=True,
    )
    # Tools registered
    names = {t.name for t in app.list_tools_sync() if hasattr(app, "list_tools_sync")} \
        if hasattr(app, "list_tools_sync") else set(app._tool_manager._tools.keys())
    for expected in {"query_events", "get_event", "get_stats", "verify_chain", "search_events"}:
        assert expected in names, f"missing tool: {expected}"
    # Resources registered
    resources = set(app._resource_manager._resources.keys())
    for expected in {
        "kernel://audit/recent",
        "kernel://stats/today",
        "kernel://chain/status",
        "kernel://policy/active",
    }:
        assert expected in resources, f"missing resource: {expected}"


def test_build_app_chain_file_missing(tmp_path, signing_keypair):
    _, _, pub_path = signing_keypair
    missing = tmp_path / "nope.jsonl"
    with pytest.raises(KernelMCPError, match="chain file not found"):
        build_app(
            chain_file=missing,
            pubkey=pub_path,
            policy=None,
            verify_on_query=True,
        )


def test_build_app_pubkey_missing_with_verify(tmp_path, sample_chain_file):
    missing = tmp_path / "no-such-key.pub"
    with pytest.raises(KernelMCPError, match="public key not found"):
        build_app(
            chain_file=sample_chain_file,
            pubkey=missing,
            policy=None,
            verify_on_query=True,
        )


def test_build_app_pubkey_missing_with_no_verify_ok(tmp_path, sample_chain_file):
    # When verify-on-query=false, missing pubkey is acceptable
    app = build_app(
        chain_file=sample_chain_file,
        pubkey=tmp_path / "no-such-key.pub",
        policy=None,
        verify_on_query=False,
    )
    assert app is not None
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
python -m pytest tests/mcp/test_server.py -v 2>&1 | head -10
```
Expected: `ImportError`.

- [ ] **Step 3: Implement `kernel/mcp/server.py`**

```python
"""kernel-mcp — stdio MCP server entry point."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from kernel.audit import AuditChainStore
from kernel.mcp.errors import KernelMCPError
from kernel.mcp.resources import register_resources
from kernel.mcp.tools import register_tools


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="kernel-mcp",
        description="kernel — read-only MCP server for audit chain query.",
    )
    parser.add_argument(
        "--chain-file",
        dest="chain_file",
        default=os.path.expanduser("~/.kernel/chain.jsonl"),
    )
    parser.add_argument(
        "--pubkey",
        dest="pubkey",
        default=os.path.expanduser("~/.kernel/keys/signing.pub"),
    )
    parser.add_argument(
        "--policy",
        dest="policy",
        default="config/policies/default.yaml",
    )
    parser.add_argument(
        "--verify-on-query",
        dest="verify_on_query",
        action="store_true",
        default=True,
    )
    parser.add_argument(
        "--no-verify-on-query",
        dest="verify_on_query",
        action="store_false",
    )
    return parser.parse_args(argv)


def build_app(
    *,
    chain_file: Path | str,
    pubkey: Path | str | None,
    policy: Path | str | None,
    verify_on_query: bool,
) -> FastMCP:
    chain_file = Path(chain_file)
    if not chain_file.exists():
        raise KernelMCPError(f"chain file not found at {chain_file}")

    pubkey_path = Path(pubkey) if pubkey else None
    if verify_on_query:
        if pubkey_path is None or not pubkey_path.exists():
            raise KernelMCPError(
                f"public key not found at {pubkey_path} — "
                "pass --pubkey or use --no-verify-on-query"
            )

    store = AuditChainStore(
        chain_file=chain_file,
        public_key_path=pubkey_path if verify_on_query else None,
        verify_on_query=verify_on_query,
    )
    store.load()

    policy_path = Path(policy) if policy else None

    app = FastMCP("kernel")
    register_tools(app, store, policy_path=policy_path)
    register_resources(app, store, policy_path=policy_path)
    return app


def run() -> None:
    ns = parse_args()
    app = build_app(
        chain_file=ns.chain_file,
        pubkey=ns.pubkey,
        policy=ns.policy,
        verify_on_query=ns.verify_on_query,
    )
    app.run(transport="stdio")


if __name__ == "__main__":
    run()
```

- [ ] **Step 4: Run server tests**

```bash
python -m pytest tests/mcp/test_server.py -v
```
Expected: 6 passed.

- [ ] **Step 5: Smoke-test the console script wires up**

```bash
pip install -e ".[mcp]" --quiet
kernel-mcp --help
```
Expected: argparse help output mentioning `--chain-file`, `--pubkey`, `--policy`, `--verify-on-query`.

- [ ] **Step 6: Commit**

```bash
git add kernel/mcp/server.py tests/mcp/test_server.py
git commit -m "Add kernel-mcp CLI entry: build_app + stdio run()"
```

---

## Task 9: Env-gated integration test (real MCP client handshake)

**Files:**
- Create: `tests/mcp/test_integration.py`

- [ ] **Step 1: Write the env-gated integration test**

```python
"""End-to-end MCP client/server handshake — env-gated by KERNEL_MCP_E2E=1."""
import asyncio
import json
import os
import sys

import pytest


@pytest.mark.integration
def test_integration_with_real_mcp_client(sample_chain_file, signing_keypair, tmp_path):
    if not os.environ.get("KERNEL_MCP_E2E"):
        pytest.skip("Set KERNEL_MCP_E2E=1 to run integration tests")

    _, _, pub_path = signing_keypair

    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m", "kernel.mcp.server",
            "--chain-file", str(sample_chain_file),
            "--pubkey", str(pub_path),
            "--no-verify-on-query",  # tmp pubkey path mismatch in subprocess env
        ],
    )

    async def _run() -> dict:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                tool_names = {t.name for t in tools.tools}
                result = await session.call_tool("query_events", {"limit": 10})
                return {"tool_names": tool_names, "first_event": result.content[0]}

    out = asyncio.run(_run())
    expected_tools = {"query_events", "get_event", "get_stats", "verify_chain", "search_events"}
    assert expected_tools.issubset(out["tool_names"])
```

- [ ] **Step 2: Run it (skipped without env var)**

```bash
python -m pytest tests/mcp/test_integration.py -v
```
Expected: 1 skipped.

- [ ] **Step 3: Run it locally with the gate set (verify it actually works)**

```bash
KERNEL_MCP_E2E=1 python -m pytest tests/mcp/test_integration.py -v
```
Expected: 1 passed.

- [ ] **Step 4: Commit**

```bash
git add tests/mcp/test_integration.py
git commit -m "Add env-gated integration test for kernel-mcp stdio handshake"
```

---

## Task 10: Docs + Claude Desktop config example + roadmap

**Files:**
- Create: `examples/mcp_claude_desktop_config.json`
- Create: `docs/integrations/mcp.md`
- Create: `docs/roadmap.md`
- Modify: `README.md`

- [ ] **Step 1: Write `examples/mcp_claude_desktop_config.json`**

```json
{
  "mcpServers": {
    "kernel": {
      "command": "kernel-mcp",
      "args": [
        "--chain-file", "/absolute/path/to/chain.jsonl",
        "--pubkey", "/absolute/path/to/signing.pub",
        "--policy", "/absolute/path/to/policies/default.yaml"
      ]
    }
  }
}
```

- [ ] **Step 2: Write `docs/integrations/mcp.md`**

```markdown
# kernel-mcp — Read-Only Audit Query Server (MCP)

`kernel-mcp` is a Model Context Protocol server that exposes the kernel
decision-audit chain to Claude Desktop (and any MCP-compatible client) over
stdio. Read-only by construction — no tool mutates audit or policy state.

## 30-Second Setup (Claude Desktop)

1. **Install the extra:**

   ```bash
   pip install kernel[mcp]
   ```

2. **Generate or point at a signed chain.** If you don't have one yet:

   ```bash
   python scripts/generate_demo_chain.py
   # → /tmp/kernel-demo/chain.jsonl + signing.pub
   ```

3. **Edit your Claude Desktop config** (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS;
   `%APPDATA%\Claude\claude_desktop_config.json` on Windows) and add:

   ```json
   {
     "mcpServers": {
       "kernel": {
         "command": "kernel-mcp",
         "args": [
           "--chain-file", "/tmp/kernel-demo/chain.jsonl",
           "--pubkey", "/tmp/kernel-demo/signing.pub"
         ]
       }
     }
   }
   ```

4. **Restart Claude Desktop.** You can now ask: *"what did my autonomous system do in the last hour?"*

## Tools

| Name | Purpose |
|---|---|
| `query_events` | Filter audit events by time / action / threat level. Returns id, timestamp, action, threat_level, sig_valid. |
| `get_event` | Full event by `chain_index` + signature + chain-link status. |
| `get_stats` | Aggregated stats for `1h`/`24h`/`7d`/`30d`/`all` windows. |
| `verify_chain` | Verify a range; returns `first_break` and `integrity`. |
| `search_events` | Case-insensitive substring search over the recursively flattened event content. |

Example invocation (via Claude Desktop):

> "Use `query_events` to fetch high-threat events from the last 24 hours."

## Resources

| URI | Payload |
|---|---|
| `kernel://audit/recent` | Last 100 events. |
| `kernel://stats/today` | Stats anchored to today's local-day boundaries on the server host. |
| `kernel://chain/status` | Integrity result + chain length. |
| `kernel://policy/active` | Metadata only — `version_id`, `version_short`, `path`, `loaded_at`. Body is not exposed. |

## Threat Model

- stdio-only transport in v1 — no network listener.
- All event payloads carry `sig_valid` (`true`/`false`/`null`). Verification failures are never silently dropped.
- The server reads from a single chain file; it never writes.
- Policy resource exposes metadata only, not the rule body.

## Roadmap

- **v1 (this release):** stdio transport, 5 read-only tools, 4 resources.
- **Phase 2:** SSE transport for remote MCP clients.
- **Phase 3:** `kernel-mcp-admin` for write operations (rotate keys, archive chain segments) — separate binary, separate auth model.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `chain file not found at <path>` | Wrong `--chain-file` path, or chain not generated yet. |
| `public key not found ...` | Pubkey path missing; pass `--pubkey` or `--no-verify-on-query`. |
| `ImportError: kernel.mcp requires the 'mcp' extra` | Run `pip install kernel[mcp]`. |
```

- [ ] **Step 3: Write `docs/roadmap.md`**

```markdown
# kernel — Roadmap

## Audit query indexing (>100K events)

`kernel-mcp` v1 runs an in-memory linear scan over the JSONL audit chain.
Adequate for the current demo profile (<10K events). When deployments
cross 100K events, revisit:

- **A.1** — in-memory time-bucket cache for `query_events` and `get_stats`.
- **A.2** — SQLite index sidecar built from JSONL on chain reload; treats
  JSONL as the source of truth, SQLite as a derived read-cache.

Defer until profiling justifies it. Premature optimisation until then.

## kernel-mcp Phase 2 — SSE transport

Stdio-only in v1; SSE will enable remote MCP clients. Requires
authentication design (likely Ed25519 signed bearer tokens against
the same key material that signs the audit chain).

## kernel-mcp Phase 3 — `kernel-mcp-admin`

Separate binary for write operations: key rotation, chain segment
archival, policy upload. Distinct auth model. Out of scope for v1.
```

- [ ] **Step 4: Modify `README.md` — add MCP section**

Insert after the "EU AI Act Compliance Reports" section and before "Integrations":

```markdown
## MCP server (Claude Desktop)

Plug kernel into Claude Desktop in ~30 seconds and ask questions like
*"what did my autonomous system do in the last hour?"*:

\`\`\`bash
pip install kernel[mcp]
\`\`\`

Then add to your Claude Desktop config:

\`\`\`json
{
  "mcpServers": {
    "kernel": {
      "command": "kernel-mcp",
      "args": ["--chain-file", "/path/to/chain.jsonl", "--pubkey", "/path/to/signing.pub"]
    }
  }
}
\`\`\`

Five read-only tools (`query_events`, `get_event`, `get_stats`,
`verify_chain`, `search_events`) and four resources cover signed audit
query, chain verification, and active-policy metadata. See
[`docs/integrations/mcp.md`](docs/integrations/mcp.md).
```

(Replace the escaped backticks `\``  with regular backticks when writing the file.)

- [ ] **Step 5: Update the roadmap checklist in README.md**

Find the existing roadmap list and add:

```markdown
- [x] MCP server interface (`kernel/mcp/`)
```

Remove the `- [ ] MCP server interface` line that was previously listed as not-yet-done.

- [ ] **Step 6: Commit**

```bash
git add examples/mcp_claude_desktop_config.json docs/integrations/mcp.md \
        docs/roadmap.md README.md
git commit -m "Add kernel-mcp docs, Claude Desktop config example, and roadmap"
```

---

## Task 11: Full suite + final commit + push

- [ ] **Step 1: Run the full test suite (excluding integration)**

```bash
python -m pytest -q -k "not integration"
```
Expected: previous 146 + ~36 new tests = ~182 passed, with all sandwich + ros2 tests still green.

- [ ] **Step 2: Run integration gate locally to confirm wiring**

```bash
KERNEL_MCP_E2E=1 python -m pytest tests/mcp/test_integration.py -v
```
Expected: 1 passed.

- [ ] **Step 3: Smoke-test the install path on a fresh venv (optional but recommended)**

```bash
python -m venv /tmp/kernel-mcp-smoke
/tmp/kernel-mcp-smoke/bin/pip install -e ".[mcp]" --quiet
/tmp/kernel-mcp-smoke/bin/kernel-mcp --help
```
Expected: argparse help renders.

- [ ] **Step 4: Final commit + push**

```bash
git push
```
Expected: push succeeds. The branch is now publishable as kernel v0.1.0 + MCP.

---

## Self-Review

**Spec coverage:**

- [x] §1 install/wire criteria → Task 10 docs + Task 1 console script + Task 1 `[mcp]` extra.
- [x] §3 architecture (single source of truth) → Task 2–4 store.
- [x] §4 file layout → File Map matches one-for-one.
- [x] §5 CLI surface (all 4 flags + defaults) → Task 8 `parse_args`.
- [x] §6 optional extra + SDK guard → Task 1.
- [x] §7 store API (init, load, reload_if_stale debounce, events/filter/get/search/verify_event/verify_chain_range) → Tasks 2–4.
- [x] §7.1 debounce semantics → Tasks 3 tests `test_reload_debounce_skips_within_window` and `test_reload_debounce_picks_up_changes_after_window`.
- [x] §7.2 recursive flatten + 200-char snippet → Task 4 `_flatten_value`, `search()`.
- [x] §7.3 verify helpers wrap existing primitives → Task 3 uses `verify_decision`/`verify_chain`.
- [x] §8 5 tool contracts → Task 6 tests cover happy + error per tool.
- [x] §9 4 resources (incl. policy metadata-only invariant) → Task 7 tests assert `rules` / `raw_bytes` not present.
- [x] §10 error contract → Tasks 6 (invalid time, limit), 7 (policy missing), 8 (chain missing, pubkey missing).
- [x] §11 11 tests → all mapped: 1→Task 8, 2/4/5/6→Task 6, 3→Task 6, 7→Task 6, 8→Task 7, 9→Task 6, 10→Task 8, 11→Task 9.
- [x] §12 roadmap note → Task 10 `docs/roadmap.md`.
- [x] §13 DoD → final pytest count + smoke test in Task 11.

**Placeholder scan:** no `TBD`/`TODO`/"implement later"/"similar to" in the steps. Every code block is complete and runnable.

**Type consistency:** `AuditChainStore` method signatures (`load`, `reload_if_stale`, `events`, `filter`, `get`, `search`, `verify_event`, `verify_chain_range`) are identical across Tasks 2–4 and consumed unchanged by Tasks 6–8. `SearchHit` and `ChainVerifyResult` dataclasses defined in Task 2 are imported in Task 5's `__init__.py` and consumed by Tasks 6–7. The `policy_path` keyword-only parameter on `register_tools` and `register_resources` is consistent between Tasks 6, 7, and 8.
