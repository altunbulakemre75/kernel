# RuntimeEvent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `RuntimeEvent` Pydantic model and audit-chain integration so that upstream evidence events (sensor monitors, guard middleware, external policy adapters) can be signed verbatim into the same JSONL chain as Decisions.

**Architecture:** Decision and RuntimeEvent share one Ed25519 signature scheme, one SHA-256 hash-link, and one monotonic `chain_index` counter. The discriminator is a `record_type: Literal["runtime_event"]` field present only on RuntimeEvent (Decisions remain unchanged for backward compatibility). MCP `query_events` is extended with field-aware filters (`event_type`/`source` for RuntimeEvent, existing `action`/`threat_level` for Decision).

**Tech Stack:** Python 3.10+, Pydantic v2, `cryptography` (Ed25519), pytest, ruff, MCP SDK (FastMCP).

**Reference spec:** `docs/superpowers/specs/2026-05-20-runtime-event-design.md`

---

## Pre-work: orient

- [ ] **Step 0.1: Read the spec end-to-end**

Read `docs/superpowers/specs/2026-05-20-runtime-event-design.md` from top to bottom (~290 lines). Sections 4 (single shared chain_index), 5 (schema), 6 (append behavior contract) are most critical.

- [ ] **Step 0.2: Check working-tree state**

Run: `git status --short`

Expected at plan start: a number of modified files from a prior style-cleanup pass (Dict → dict typing modernization, unused-import removal — 33 files at time of writing). These changes are unrelated to RuntimeEvent.

**Decision point** (ask the user if unsure):
- If the user wants the cleanup committed first → make that commit before starting Task 1, so this feature's diff stays focused.
- If the user wants the cleanup set aside → `git stash push -u -m "pre-runtime-event-cleanup"` before Task 1, restore afterwards.
- If the user wants them mixed → proceed; flag at the end that the final commit graph contains unrelated changes.

Do NOT silently include the cleanup changes in this feature's commits.

- [ ] **Step 0.3: Verify baseline tests pass**

Run: `pytest -q`
Expected: ~192 tests pass. Note the exact count for later regression check.

If FAIL: do not proceed. Investigate baseline failures first (they may be from the uncommitted style changes or pre-existing).

- [ ] **Step 0.4: Verify ruff is clean**

Run: `ruff check .`
Expected: clean (or note any pre-existing warnings to ignore later).

---

## Task 1: RuntimeEvent schema + PayloadTooLargeError

**Files:**
- Modify: `shared/schemas.py`
- Create: `tests/test_runtime_event.py`

This task defines the type, the size constraint, and the source_id validator. Three tests prove the schema contract.

- [ ] **Step 1.1: Create test file skeleton**

Create `tests/test_runtime_event.py`:

```python
"""Tests for RuntimeEvent — upstream evidence events signed into the audit chain."""
from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from shared.schemas import (
    PayloadTooLargeError,
    RUNTIME_EVENT_PAYLOAD_MAX_BYTES,
    RuntimeEvent,
)


def _valid_event_kwargs() -> dict:
    return {
        "event_type": "sensor_anomaly",
        "source": "lidar_monitor",
        "source_id": "lidar-front-01",
        "timestamp_iso": "2026-05-20T12:00:00+00:00",
        "payload": {"distance_m": 4.2, "object_class": "vehicle"},
    }
```

- [ ] **Step 1.2: Write test_runtime_event_creation**

Append to `tests/test_runtime_event.py`:

```python
def test_runtime_event_creation():
    ev = RuntimeEvent(**_valid_event_kwargs())

    # Discriminator and defaults
    assert ev.record_type == "runtime_event"
    assert ev.context == {}
    assert ev.chain_index == 0
    assert ev.signature is None
    assert ev.prev_hash is None
    assert ev.payload_hash is None
    assert ev.policy_version_id is None

    # User-supplied fields preserved verbatim
    assert ev.event_type == "sensor_anomaly"
    assert ev.source == "lidar_monitor"
    assert ev.source_id == "lidar-front-01"
    assert ev.payload == {"distance_m": 4.2, "object_class": "vehicle"}
```

- [ ] **Step 1.3: Run test, verify failure**

Run: `pytest tests/test_runtime_event.py::test_runtime_event_creation -v`
Expected: FAIL with `ImportError` (PayloadTooLargeError / RUNTIME_EVENT_PAYLOAD_MAX_BYTES / RuntimeEvent not defined).

- [ ] **Step 1.4: Add minimal RuntimeEvent + exports to shared/schemas.py**

Modify `shared/schemas.py`. Add at the top of the file (after existing imports):

```python
import json
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

# Module-level constant — RuntimeEvent.payload JSON-serialized byte limit.
# Audit chain bloat'u önler; sensor monitor / guard middleware için 64KB yeter.
# Configurable: production operators override edebilir.
RUNTIME_EVENT_PAYLOAD_MAX_BYTES = 64 * 1024  # 64 KB


class PayloadTooLargeError(ValueError):
    """Raised when RuntimeEvent.payload exceeds RUNTIME_EVENT_PAYLOAD_MAX_BYTES.

    Subclass of ValueError so Pydantic wraps it in ValidationError when raised
    inside a field_validator. The original exception type is preserved in the
    error context for test assertions and structured logging.
    """


class RuntimeEvent(BaseModel):
    """Upstream evidence event from external systems (sensor monitors,
    guard middleware, external policy adapters). Signed verbatim into
    the audit chain alongside Decision records."""

    record_type: Literal["runtime_event"] = "runtime_event"

    event_type: str
    source: str
    source_id: str = Field(min_length=1, max_length=256)
    timestamp_iso: str
    payload: dict[str, Any]
    context: dict[str, Any] = Field(default_factory=dict)

    # Audit chain fields (filled by chain when signed)
    signature: str | None = None
    prev_hash: str | None = None
    payload_hash: str | None = None
    chain_index: int = 0
    policy_version_id: str | None = None
```

**Important:** if `shared/schemas.py` already has `from typing import Any` and `from pydantic import BaseModel`, do not duplicate. Merge into existing imports.

- [ ] **Step 1.5: Run creation test, verify pass**

Run: `pytest tests/test_runtime_event.py::test_runtime_event_creation -v`
Expected: PASS.

- [ ] **Step 1.6: Write test_payload_size_limit_enforced**

Append to `tests/test_runtime_event.py`:

```python
def test_payload_size_limit_enforced():
    # 1 byte under the limit must pass
    just_under = "x" * (RUNTIME_EVENT_PAYLOAD_MAX_BYTES - 100)
    kwargs = _valid_event_kwargs() | {"payload": {"blob": just_under}}
    ev = RuntimeEvent(**kwargs)
    assert ev.payload["blob"] == just_under

    # Over the limit must raise PayloadTooLargeError (wrapped in ValidationError)
    too_big = "x" * (RUNTIME_EVENT_PAYLOAD_MAX_BYTES + 1)
    kwargs = _valid_event_kwargs() | {"payload": {"blob": too_big}}
    with pytest.raises(ValidationError) as exc_info:
        RuntimeEvent(**kwargs)

    # The original PayloadTooLargeError must be in the error context
    errors = exc_info.value.errors()
    assert any("payload exceeds" in str(e.get("msg", "")).lower() for e in errors)
```

- [ ] **Step 1.7: Run size-limit test, verify failure**

Run: `pytest tests/test_runtime_event.py::test_payload_size_limit_enforced -v`
Expected: FAIL — validator not yet defined, oversized payload accepted.

- [ ] **Step 1.8: Add payload size validator**

Modify `shared/schemas.py` — add to the `RuntimeEvent` class body (after the field definitions):

```python
    @field_validator("payload")
    @classmethod
    def _validate_payload_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        size = len(json.dumps(v, separators=(",", ":")).encode("utf-8"))
        if size > RUNTIME_EVENT_PAYLOAD_MAX_BYTES:
            raise PayloadTooLargeError(
                f"payload exceeds {RUNTIME_EVENT_PAYLOAD_MAX_BYTES} bytes "
                f"(got {size} bytes); use file references or chunking for "
                f"larger evidence."
            )
        return v
```

- [ ] **Step 1.9: Run size-limit test, verify pass**

Run: `pytest tests/test_runtime_event.py::test_payload_size_limit_enforced -v`
Expected: PASS.

- [ ] **Step 1.10: Write test_source_id_constraints**

Append to `tests/test_runtime_event.py`:

```python
def test_source_id_constraints():
    # Empty source_id rejected
    kwargs = _valid_event_kwargs() | {"source_id": ""}
    with pytest.raises(ValidationError):
        RuntimeEvent(**kwargs)

    # 257-char source_id rejected (one over max)
    kwargs = _valid_event_kwargs() | {"source_id": "x" * 257}
    with pytest.raises(ValidationError):
        RuntimeEvent(**kwargs)

    # 1-char source_id accepted (min boundary)
    kwargs = _valid_event_kwargs() | {"source_id": "x"}
    assert RuntimeEvent(**kwargs).source_id == "x"

    # 256-char source_id accepted (max boundary)
    kwargs = _valid_event_kwargs() | {"source_id": "x" * 256}
    assert RuntimeEvent(**kwargs).source_id == "x" * 256
```

- [ ] **Step 1.11: Run source_id test, verify pass**

Run: `pytest tests/test_runtime_event.py::test_source_id_constraints -v`
Expected: PASS — Field constraints from Step 1.4 already enforce this.

If it FAILS, double-check Step 1.4 included `source_id: str = Field(min_length=1, max_length=256)`.

- [ ] **Step 1.12: Run all Task 1 tests + the regression suite**

Run: `pytest tests/test_runtime_event.py -v`
Expected: 3 PASS.

Then run full suite to catch regressions:
Run: `pytest -q`
Expected: ~192 (baseline) + 3 = ~195 tests pass.

- [ ] **Step 1.13: Run ruff**

Run: `ruff check shared/schemas.py tests/test_runtime_event.py`
Expected: clean.

If failures: fix in place (likely unused imports or line-length).

- [ ] **Step 1.14: Commit Task 1**

```bash
git add shared/schemas.py tests/test_runtime_event.py
git commit -m "Add RuntimeEvent schema + PayloadTooLargeError (64KB payload limit)"
```

---

## Task 2: append_runtime_event + caller-fields-overwritten contract

**Files:**
- Modify: `services/decision/audit_chain.py`
- Modify: `tests/test_runtime_event.py`

This task adds the file-writing entry point. Tests cover: (a) basic single-event append, (b) the security contract that caller-provided chain fields are overwritten.

- [ ] **Step 2.1: Add shared signing-key fixture to test file**

Append to `tests/test_runtime_event.py` (after the `_valid_event_kwargs` helper):

```python
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


@pytest.fixture
def signing_key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture
def public_key(signing_key):
    return signing_key.public_key()
```

- [ ] **Step 2.2: Write test_append_single_runtime_event**

Append to `tests/test_runtime_event.py`:

```python
def test_append_single_runtime_event(tmp_path: Path, signing_key, public_key):
    from services.decision.audit_chain import (
        append_runtime_event,
        verify_decision,
    )

    chain_path = tmp_path / "chain.jsonl"
    ev = RuntimeEvent(**_valid_event_kwargs())

    signed = append_runtime_event(
        event=ev,
        chain_path=chain_path,
        signing_key=signing_key,
        policy_version_id="p_test_v1",
    )

    # Returned instance has chain fields filled
    assert signed.chain_index == 0
    assert signed.prev_hash is None
    assert signed.payload_hash is not None and len(signed.payload_hash) == 64  # SHA-256 hex
    assert signed.signature is not None and len(signed.signature) > 0
    assert signed.policy_version_id == "p_test_v1"
    assert signed.record_type == "runtime_event"

    # File contains exactly one signed line, which verifies
    lines = chain_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    on_disk = json.loads(lines[0])
    assert on_disk["record_type"] == "runtime_event"
    assert verify_decision(on_disk, public_key) is True
```

- [ ] **Step 2.3: Run test, verify failure**

Run: `pytest tests/test_runtime_event.py::test_append_single_runtime_event -v`
Expected: FAIL — `append_runtime_event` not yet defined.

- [ ] **Step 2.4: Implement append_runtime_event**

Modify `services/decision/audit_chain.py`. At the top of the file, add `Path` import:

```python
import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from shared.schemas import RuntimeEvent
```

At the end of `services/decision/audit_chain.py`, append:

```python
def _read_last_entry(chain_path: Path) -> dict[str, Any] | None:
    """Read and parse the last JSONL line of chain_path, or None if file missing/empty."""
    if not chain_path.exists():
        return None
    lines = [
        line for line in chain_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not lines:
        return None
    return json.loads(lines[-1])


def append_runtime_event(
    event: RuntimeEvent,
    chain_path: Path,
    signing_key: ed25519.Ed25519PrivateKey,
    policy_version_id: str,
) -> RuntimeEvent:
    """Sign and append a RuntimeEvent to the JSONL audit chain.

    All chain fields on the input event (signature, prev_hash, payload_hash,
    chain_index, policy_version_id) are overwritten by this function — caller
    values are discarded. This is a security contract: caller cannot pre-set
    chain_index or signature to compromise integrity.

    See spec: docs/superpowers/specs/2026-05-20-runtime-event-design.md §6.
    """
    last = _read_last_entry(chain_path)
    if last is None:
        prev_hash: str | None = None
        next_index = 0
    else:
        prev_hash = last.get("payload_hash")
        next_index = int(last.get("chain_index", -1)) + 1

    # Build the dict that will be signed. We pass model_dump() so the validator
    # has already run (payload size, source_id constraints) — by the time we get
    # here the event is structurally valid.
    payload_dict: dict[str, Any] = event.model_dump()
    payload_dict["chain_index"] = next_index
    payload_dict["policy_version_id"] = policy_version_id
    # Strip any caller-provided chain fields — sign_decision will refill them.
    payload_dict.pop("signature", None)
    payload_dict.pop("payload_hash", None)
    payload_dict["prev_hash"] = prev_hash

    signed_dict = sign_decision(
        decision=payload_dict,
        prev_hash=prev_hash,
        signing_key=signing_key,
    )

    # Append signed line to chain file (single-writer assumption — no locking).
    with open(chain_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(signed_dict, separators=(",", ":")) + "\n")
        f.flush()

    return RuntimeEvent(**signed_dict)
```

- [ ] **Step 2.5: Run test, verify pass**

Run: `pytest tests/test_runtime_event.py::test_append_single_runtime_event -v`
Expected: PASS.

- [ ] **Step 2.6: Write test_caller_provided_chain_fields_are_overwritten**

Append to `tests/test_runtime_event.py`:

```python
def test_caller_provided_chain_fields_are_overwritten(
    tmp_path: Path, signing_key, public_key
):
    """Security contract: caller-supplied chain fields must be discarded.
    Malicious or buggy callers cannot break chain integrity."""
    from services.decision.audit_chain import (
        append_runtime_event,
        verify_decision,
    )

    chain_path = tmp_path / "chain.jsonl"

    # Caller tries to inject bogus chain fields
    ev = RuntimeEvent(
        **_valid_event_kwargs(),
        signature="fakefakefake==",
        prev_hash="ff" * 32,
        payload_hash="bad" * 21 + "b",  # 64 chars
        chain_index=999,
        policy_version_id="injected_by_caller",
    )

    signed = append_runtime_event(
        event=ev,
        chain_path=chain_path,
        signing_key=signing_key,
        policy_version_id="legitimate_v1",
    )

    # All five caller-provided values must have been overwritten
    assert signed.chain_index == 0  # not 999
    assert signed.prev_hash is None  # not "ff"*32 (first entry, genesis)
    assert signed.payload_hash != "bad" * 21 + "b"  # real SHA-256 of canonical bytes
    assert signed.signature != "fakefakefake=="  # real Ed25519 signature
    assert signed.policy_version_id == "legitimate_v1"  # from function param

    # And the signed line on disk verifies correctly
    on_disk = json.loads(chain_path.read_text(encoding="utf-8").strip())
    assert verify_decision(on_disk, public_key) is True
```

- [ ] **Step 2.7: Run test, verify pass**

Run: `pytest tests/test_runtime_event.py::test_caller_provided_chain_fields_are_overwritten -v`
Expected: PASS — implementation from Step 2.4 already overwrites all chain fields.

If it FAILS, inspect `append_runtime_event` for paths that respect caller values. The `payload_dict.pop("signature", ...)` and explicit `chain_index`/`prev_hash`/`policy_version_id` assignments are critical.

- [ ] **Step 2.8: Update sign_decision docstring (polymorphic note)**

Modify `services/decision/audit_chain.py`. Replace the existing `sign_decision` function (find the line `def sign_decision(decision: dict[str, Any], prev_hash: str | None, signing_key: ed25519.Ed25519PrivateKey) -> dict[str, Any]:`) with the same signature but enhanced docstring:

```python
def sign_decision(decision: dict[str, Any], prev_hash: str | None, signing_key: ed25519.Ed25519PrivateKey) -> dict[str, Any]:
    """Sign an audit chain entry with Ed25519 + SHA-256 hash linking.

    Polymorphic: works for Decision dicts AND RuntimeEvent dicts. The
    function does not inspect record type; it canonicalizes the dict
    (excluding signature/payload_hash), computes payload_hash, signs the
    canonical JSON, and returns the dict with signature, payload_hash,
    prev_hash, and chain_index set.
    """
    signed_decision = decision.copy()
    signed_decision["prev_hash"] = prev_hash
    signed_decision["chain_index"] = decision.get("chain_index", 0)

    payload = canonical_json(signed_decision)
    payload_hash = sha256_hex(payload)

    sig = signing_key.sign(payload)

    signed_decision["payload_hash"] = payload_hash
    signed_decision["signature"] = base64.b64encode(sig).decode("utf-8")

    return signed_decision
```

(Only the docstring is new — the body is unchanged. Verify body matches existing.)

- [ ] **Step 2.9: Run Task 2 tests + regression check**

Run: `pytest tests/test_runtime_event.py -v`
Expected: 5 PASS (3 from Task 1, 2 from Task 2).

Run: `pytest -q`
Expected: ~192 + 5 = ~197 PASS, 0 fail.

- [ ] **Step 2.10: Run ruff**

Run: `ruff check services/decision/audit_chain.py tests/test_runtime_event.py`
Expected: clean.

- [ ] **Step 2.11: Commit Task 2**

```bash
git add services/decision/audit_chain.py tests/test_runtime_event.py
git commit -m "Add append_runtime_event() with caller-overwrite security contract"
```

---

## Task 3: Mixed-chain verification + verify_runtime_event alias

**Files:**
- Modify: `services/decision/audit_chain.py`
- Modify: `tests/test_runtime_event.py`

`verify_decision` and `verify_chain` are already polymorphic. This task adds:
- A thin `verify_runtime_event` alias (so calling code can be type-explicit).
- Three tests proving the existing verify logic handles mixed Decision+RuntimeEvent chains.

- [ ] **Step 3.1: Write a sign_decision-helper for Decisions in tests**

Append to `tests/test_runtime_event.py` (after fixtures, before tests):

```python
def _append_decision_directly(
    chain_path: Path,
    decision: dict,
    signing_key,
) -> dict:
    """Test helper: sign a Decision-like dict and append to chain.
    Uses the same primitives as append_runtime_event for chain continuity."""
    from services.decision.audit_chain import _read_last_entry, sign_decision

    last = _read_last_entry(chain_path)
    if last is None:
        prev_hash = None
        next_index = 0
    else:
        prev_hash = last.get("payload_hash")
        next_index = int(last.get("chain_index", -1)) + 1

    payload_dict = dict(decision)
    payload_dict["chain_index"] = next_index
    payload_dict["prev_hash"] = prev_hash
    payload_dict.pop("signature", None)
    payload_dict.pop("payload_hash", None)

    signed = sign_decision(
        decision=payload_dict,
        prev_hash=prev_hash,
        signing_key=signing_key,
    )

    with open(chain_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(signed, separators=(",", ":")) + "\n")

    return signed


def _decision_dict(timestamp_iso: str, action: str = "allow") -> dict:
    return {
        "timestamp_iso": timestamp_iso,
        "action": action,
        "threat_level": "low",
        "policy_version_id": "p_test",
        "metadata": {"rule_id": "r_001"},
    }
```

- [ ] **Step 3.2: Write test_mixed_chain_decision_then_runtime**

Append to `tests/test_runtime_event.py`:

```python
def test_mixed_chain_decision_then_runtime(
    tmp_path: Path, signing_key, public_key
):
    from services.decision.audit_chain import (
        append_runtime_event,
        verify_chain,
    )

    chain_path = tmp_path / "chain.jsonl"

    # idx=0: Decision
    _append_decision_directly(
        chain_path,
        _decision_dict("2026-05-20T12:00:00+00:00", "allow"),
        signing_key,
    )

    # idx=1: RuntimeEvent
    ev1 = RuntimeEvent(**_valid_event_kwargs())
    append_runtime_event(ev1, chain_path, signing_key, "p_test")

    # idx=2: Decision
    _append_decision_directly(
        chain_path,
        _decision_dict("2026-05-20T12:00:02+00:00", "block"),
        signing_key,
    )

    # Read the full chain and verify integrity
    lines = chain_path.read_text(encoding="utf-8").strip().splitlines()
    entries = [json.loads(line) for line in lines]
    assert len(entries) == 3

    # Chain indices are a single shared sequence: 0, 1, 2
    assert [e["chain_index"] for e in entries] == [0, 1, 2]

    # verify_chain returns (True, None) for the whole mixed chain
    ok, broken_idx = verify_chain(entries, public_key)
    assert ok is True
    assert broken_idx is None
```

- [ ] **Step 3.3: Run test, verify pass**

Run: `pytest tests/test_runtime_event.py::test_mixed_chain_decision_then_runtime -v`
Expected: PASS — `verify_chain` is already type-agnostic; no code changes needed yet.

If it FAILS, the failure is most likely chain_index drift. Inspect the `_append_decision_directly` helper and confirm it reads the last entry like `append_runtime_event` does.

- [ ] **Step 3.4: Write test_prev_hash_integrity_mixed**

Append to `tests/test_runtime_event.py`:

```python
def test_prev_hash_integrity_mixed(
    tmp_path: Path, signing_key, public_key
):
    """Each entry's prev_hash must equal the previous entry's payload_hash,
    regardless of record_type. This is the explicit single-monotonic-chain rule."""
    from services.decision.audit_chain import append_runtime_event

    chain_path = tmp_path / "chain.jsonl"

    # idx=0: RuntimeEvent (genesis)
    ev0 = RuntimeEvent(**(_valid_event_kwargs() | {"event_type": "boot"}))
    append_runtime_event(ev0, chain_path, signing_key, "p_test")

    # idx=1: Decision
    _append_decision_directly(
        chain_path,
        _decision_dict("2026-05-20T12:00:01+00:00", "allow"),
        signing_key,
    )

    # idx=2: RuntimeEvent
    ev2 = RuntimeEvent(**(_valid_event_kwargs() | {"event_type": "shutdown"}))
    append_runtime_event(ev2, chain_path, signing_key, "p_test")

    entries = [
        json.loads(line)
        for line in chain_path.read_text(encoding="utf-8").strip().splitlines()
    ]

    # Walk the chain: each prev_hash matches the previous payload_hash
    assert entries[0]["prev_hash"] is None  # genesis
    assert entries[1]["prev_hash"] == entries[0]["payload_hash"]
    assert entries[2]["prev_hash"] == entries[1]["payload_hash"]

    # And the record types are interleaved as expected
    types = [e.get("record_type", "decision") for e in entries]
    assert types == ["runtime_event", "decision", "runtime_event"]
```

- [ ] **Step 3.5: Run test, verify pass**

Run: `pytest tests/test_runtime_event.py::test_prev_hash_integrity_mixed -v`
Expected: PASS.

- [ ] **Step 3.6: Write test_payload_tampering_detected**

Append to `tests/test_runtime_event.py`:

```python
def test_payload_tampering_detected(
    tmp_path: Path, signing_key, public_key
):
    from services.decision.audit_chain import (
        append_runtime_event,
        verify_decision,
    )

    chain_path = tmp_path / "chain.jsonl"
    ev = RuntimeEvent(**_valid_event_kwargs())
    append_runtime_event(ev, chain_path, signing_key, "p_test")

    # Read the signed line, tamper with payload, write it back
    line = chain_path.read_text(encoding="utf-8").strip()
    entry = json.loads(line)
    assert verify_decision(entry, public_key) is True  # baseline

    entry["payload"]["object_class"] = "pedestrian"  # was "vehicle" — tamper
    chain_path.write_text(json.dumps(entry, separators=(",", ":")) + "\n", encoding="utf-8")

    # Re-read and verify — signature must no longer match
    tampered = json.loads(chain_path.read_text(encoding="utf-8").strip())
    assert verify_decision(tampered, public_key) is False
```

- [ ] **Step 3.7: Run test, verify pass**

Run: `pytest tests/test_runtime_event.py::test_payload_tampering_detected -v`
Expected: PASS — `verify_decision` recomputes `canonical_json(payload)` and the SHA-256 mismatch fails verification.

- [ ] **Step 3.8: Add verify_runtime_event alias + docstring updates**

Modify `services/decision/audit_chain.py`. Find the existing `verify_decision` function and replace its docstring (body unchanged):

```python
def verify_decision(decision: dict[str, Any], public_key: ed25519.Ed25519PublicKey) -> bool:
    """Verify an audit chain entry's signature.

    Polymorphic: works for Decision dicts AND RuntimeEvent dicts. Type-agnostic;
    only checks payload_hash and Ed25519 signature against the canonical JSON.
    """
    try:
        signature = decision.get("signature")
        if not signature:
            return False

        payload = canonical_json(decision)
        if decision.get("payload_hash") != sha256_hex(payload):
            return False

        sig_bytes = base64.b64decode(signature)
        public_key.verify(sig_bytes, payload)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
```

Find the existing `verify_chain` function and replace its docstring (body unchanged):

```python
def verify_chain(decisions: list[dict[str, Any]], public_key: ed25519.Ed25519PublicKey) -> tuple[bool, int | None]:
    """Verify a contiguous slice of the audit chain.

    Handles mixed Decision + RuntimeEvent chains. `chain_index` is a single
    monotonically increasing counter shared across both record types — this
    function walks it linearly and verifies each entry's signature + hash-link.

    Returns:
        (True, None) if all entries verify.
        (False, first_bad_index) if any entry fails verification or breaks the
        prev_hash chain or chain_index sequence.
    """
    if not decisions:
        return True, None
    # ... rest unchanged
```

Then, at the end of the file, append the thin alias:

```python
def verify_runtime_event(event: dict[str, Any], public_key: ed25519.Ed25519PublicKey) -> bool:
    """Verify a RuntimeEvent's signature. Thin alias over verify_decision
    (which is already type-agnostic) — exists so calling code can express
    intent explicitly."""
    return verify_decision(event, public_key)
```

- [ ] **Step 3.9: Smoke-test the alias**

Append to `tests/test_runtime_event.py`:

```python
def test_verify_runtime_event_alias(tmp_path: Path, signing_key, public_key):
    from services.decision.audit_chain import (
        append_runtime_event,
        verify_runtime_event,
    )

    chain_path = tmp_path / "chain.jsonl"
    ev = RuntimeEvent(**_valid_event_kwargs())
    append_runtime_event(ev, chain_path, signing_key, "p_test")

    entry = json.loads(chain_path.read_text(encoding="utf-8").strip())
    assert verify_runtime_event(entry, public_key) is True
```

Run: `pytest tests/test_runtime_event.py::test_verify_runtime_event_alias -v`
Expected: PASS.

- [ ] **Step 3.10: Run Task 3 tests + regression check**

Run: `pytest tests/test_runtime_event.py -v`
Expected: 9 PASS (3 from Task 1, 2 from Task 2, 4 from Task 3).

Run: `pytest -q`
Expected: ~192 + 9 = ~201 PASS, 0 fail.

- [ ] **Step 3.11: Run ruff**

Run: `ruff check services/decision/audit_chain.py tests/test_runtime_event.py`
Expected: clean.

- [ ] **Step 3.12: Commit Task 3**

```bash
git add services/decision/audit_chain.py tests/test_runtime_event.py
git commit -m "Verify mixed Decision+RuntimeEvent chains; add verify_runtime_event alias"
```

---

## Task 4: AuditChainStore field-aware filter

**Files:**
- Modify: `kernel/audit/store.py`
- Modify: `tests/audit/test_store.py` (extend existing)

This task extends `AuditChainStore.filter()` so `action`/`threat_level` filters only return Decisions and `event_type`/`source` filters only return RuntimeEvents.

- [ ] **Step 4.1: Read existing tests/audit/test_store.py top section to learn fixtures**

Open `tests/audit/test_store.py` and look at:
- How `sample_chain_file` fixture is consumed (from `tests/audit/conftest.py`).
- The current `filter()` test patterns.

This is read-only: we are about to add a test that uses the same conftest fixture style.

- [ ] **Step 4.1a: Read tests/audit/conftest.py to confirm symbols before extending**

Open `tests/audit/conftest.py` and confirm:
- `_BASE_TS` exists (used by mixed_chain_file fixture in Step 4.2)
- `_write_chain` helper exists (or note its actual name/signature)
- `_raw_events` helper exists (or note its actual name)
- `signing_keypair` fixture exists and returns a tuple of `(sk, pub, pub_path)`
- The imports at the top (so we know whether to add `from datetime import timedelta`, etc.)

If any of these names differ from what Step 4.2 assumes, update Step 4.2's fixture code to match the actual names BEFORE writing. Do not assume — read first.

- [ ] **Step 4.2: Add mixed-chain fixture to tests/audit/conftest.py**

Modify `tests/audit/conftest.py`. At the end of the file, append:

```python
from shared.schemas import RuntimeEvent
from services.decision.audit_chain import append_runtime_event


@pytest.fixture
def mixed_chain_file(tmp_path: Path, signing_keypair) -> Path:
    """A chain with 4 entries interleaved: Decision, RuntimeEvent, Decision, RuntimeEvent."""
    sk, _, _ = signing_keypair
    chain_file = tmp_path / "mixed.jsonl"

    # Two Decisions via existing helper
    _write_chain(chain_file, _raw_events()[:2], sk)

    # Two RuntimeEvents on top
    ev0 = RuntimeEvent(
        event_type="sensor_anomaly",
        source="lidar_monitor",
        source_id="lidar-front-01",
        timestamp_iso=(_BASE_TS + timedelta(seconds=5)).isoformat(),
        payload={"distance_m": 4.2},
    )
    append_runtime_event(ev0, chain_file, sk, "p_test")

    ev1 = RuntimeEvent(
        event_type="guardrail_downgrade",
        source="kinematic_guard",
        source_id="kg-main",
        timestamp_iso=(_BASE_TS + timedelta(seconds=15)).isoformat(),
        payload={"reason": "speed_exceeded"},
    )
    append_runtime_event(ev1, chain_file, sk, "p_test")

    return chain_file
```

- [ ] **Step 4.3: Write field-aware filter test**

Append to `tests/audit/test_store.py`:

```python
def test_filter_action_only_returns_decisions(mixed_chain_file, signing_keypair):
    """action filter must return ONLY Decision entries; RuntimeEvents (which
    have no action field) are excluded."""
    from kernel.audit.store import AuditChainStore

    _, _, pub_path = signing_keypair
    store = AuditChainStore(mixed_chain_file, public_key_path=pub_path)
    store.load()

    results = store.filter(action="allow", limit=100)
    assert len(results) > 0
    for ev in results:
        assert ev.get("action") == "allow"
        assert ev.get("record_type", "decision") == "decision"


def test_filter_event_type_only_returns_runtime_events(mixed_chain_file, signing_keypair):
    """event_type filter must return ONLY RuntimeEvent entries."""
    from kernel.audit.store import AuditChainStore

    _, _, pub_path = signing_keypair
    store = AuditChainStore(mixed_chain_file, public_key_path=pub_path)
    store.load()

    results = store.filter(event_type="sensor_anomaly", limit=100)
    assert len(results) == 1
    assert results[0]["event_type"] == "sensor_anomaly"
    assert results[0]["record_type"] == "runtime_event"


def test_filter_source_only_returns_runtime_events(mixed_chain_file, signing_keypair):
    """source filter must return ONLY RuntimeEvent entries."""
    from kernel.audit.store import AuditChainStore

    _, _, pub_path = signing_keypair
    store = AuditChainStore(mixed_chain_file, public_key_path=pub_path)
    store.load()

    results = store.filter(source="kinematic_guard", limit=100)
    assert len(results) == 1
    assert results[0]["source"] == "kinematic_guard"
    assert results[0]["record_type"] == "runtime_event"


def test_filter_no_filters_returns_all(mixed_chain_file, signing_keypair):
    """No filters → all entries (both Decisions and RuntimeEvents)."""
    from kernel.audit.store import AuditChainStore

    _, _, pub_path = signing_keypair
    store = AuditChainStore(mixed_chain_file, public_key_path=pub_path)
    store.load()

    results = store.filter(limit=100)
    types = {ev.get("record_type", "decision") for ev in results}
    assert types == {"decision", "runtime_event"}
    assert len(results) == 4  # 2 Decisions + 2 RuntimeEvents
```

- [ ] **Step 4.4: Run tests, verify failure**

Run: `pytest tests/audit/test_store.py::test_filter_event_type_only_returns_runtime_events -v`
Expected: FAIL — `filter()` does not yet accept `event_type` keyword argument.

- [ ] **Step 4.5: Extend AuditChainStore.filter() signature**

Modify `kernel/audit/store.py`. Replace the existing `filter` method body with:

```python
    def filter(
        self,
        *,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        action: str | None = None,
        threat_level: str | None = None,
        event_type: str | None = None,
        source: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        # Determine which record types the filters target.
        decision_filter_active = action is not None or threat_level is not None
        runtime_filter_active = event_type is not None or source is not None

        results = []
        for ev in self._events:
            record_type = ev.get("record_type", "decision")

            # Field-aware exclusion: a Decision-only filter excludes
            # RuntimeEvents (and vice versa).
            if decision_filter_active and record_type != "decision":
                continue
            if runtime_filter_active and record_type != "runtime_event":
                continue

            if action is not None and ev.get("action") != action:
                continue
            if threat_level is not None and ev.get("threat_level") != threat_level:
                continue
            if event_type is not None and ev.get("event_type") != event_type:
                continue
            if source is not None and ev.get("source") != source:
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

- [ ] **Step 4.6: Run new tests, verify pass**

Run: `pytest tests/audit/test_store.py::test_filter_action_only_returns_decisions tests/audit/test_store.py::test_filter_event_type_only_returns_runtime_events tests/audit/test_store.py::test_filter_source_only_returns_runtime_events tests/audit/test_store.py::test_filter_no_filters_returns_all -v`
Expected: 4 PASS.

- [ ] **Step 4.7: Run regression — all existing tests/audit tests pass**

Run: `pytest tests/audit/ -v`
Expected: all existing AuditChainStore tests still pass + the 4 new ones.

- [ ] **Step 4.8: Run full regression**

Run: `pytest -q`
Expected: ~192 + 9 (Task 1-3) + 4 (Task 4) = ~205 PASS.

- [ ] **Step 4.9: Run ruff**

Run: `ruff check kernel/audit/store.py tests/audit/test_store.py tests/audit/conftest.py`
Expected: clean.

- [ ] **Step 4.10: Commit Task 4**

```bash
git add kernel/audit/store.py tests/audit/test_store.py tests/audit/conftest.py
git commit -m "AuditChainStore.filter(): field-aware semantics (Decision vs RuntimeEvent)"
```

---

## Task 5: MCP schemas + tools (query_events extension + record_type-aware summary)

**Files:**
- Modify: `kernel/mcp/schemas.py`
- Modify: `kernel/mcp/tools.py`
- Modify: `tests/test_runtime_event.py`

This task plumbs RuntimeEvent through MCP: `EventSummary` and `SearchHit` gain `record_type`/`event_type`/`source`, `query_events` accepts the new filter parameters, and `_summary()` is record-type aware.

- [ ] **Step 5.0: Inspect FastMCP tool access pattern (check before assume)**

Open `tests/mcp/test_server.py` (and any other file under `tests/mcp/` that exercises a registered tool — likely `test_resources.py` for the resource counterpart) and find how the test code invokes a registered `@app.tool()` function. There are several possible patterns depending on FastMCP version:

- `app._tool_manager._tools[name].fn(...)` — used in newer FastMCP
- `app._tools[name].fn(...)` — older
- A helper that goes through `app.list_tools()` + `app.call_tool()`
- The implementation is extracted into a module-level helper and tested directly (bypass the decorator)

Note the canonical pattern used in this repo. **Use that pattern verbatim in Step 5.1's test code**, overriding the placeholder `app._tool_manager._tools` access I sketched there. Do not write the test until you have read the pattern.

If `tests/mcp/test_server.py` does not exercise a registered tool by calling it (e.g., it only checks that registration succeeds), look at `tests/mcp/test_resources.py` or any other tools-related test for the calling pattern.

- [ ] **Step 5.1: Write the MCP integration test**

Append to `tests/test_runtime_event.py`:

```python
def test_mcp_query_events_filters_by_event_type(
    tmp_path: Path, signing_key, public_key
):
    """End-to-end: MCP query_events with event_type filter returns only
    matching RuntimeEvents from a mixed chain; action filter returns only Decisions."""
    from mcp.server.fastmcp import FastMCP

    from kernel.audit.store import AuditChainStore
    from kernel.mcp.tools import register_tools
    from services.decision.audit_chain import append_runtime_event

    chain_path = tmp_path / "chain.jsonl"
    pub_path = tmp_path / "signing.pub"
    pub_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    # idx=0: Decision (allow)
    _append_decision_directly(
        chain_path,
        _decision_dict("2026-05-20T12:00:00+00:00", "allow"),
        signing_key,
    )

    # idx=1: RuntimeEvent (sensor_anomaly)
    append_runtime_event(
        RuntimeEvent(**(_valid_event_kwargs() | {"event_type": "sensor_anomaly"})),
        chain_path, signing_key, "p_test",
    )

    # idx=2: RuntimeEvent (guardrail_downgrade)
    append_runtime_event(
        RuntimeEvent(**(_valid_event_kwargs() | {
            "event_type": "guardrail_downgrade",
            "source": "kinematic_guard",
        })),
        chain_path, signing_key, "p_test",
    )

    # idx=3: Decision (block)
    _append_decision_directly(
        chain_path,
        _decision_dict("2026-05-20T12:00:03+00:00", "block"),
        signing_key,
    )

    store = AuditChainStore(chain_path, public_key_path=pub_path)
    store.load()
    app = FastMCP("test")
    register_tools(app, store)

    # Grab the registered functions by name. FastMCP's internal API for this
    # may vary between versions. Recommended: before writing this test, open
    # `tests/mcp/test_server.py` to see the canonical access pattern used in
    # this repo and mirror it. The pattern below uses `_tool_manager._tools`
    # which works for fastmcp >= 1.x (each entry has a `.fn` attribute).
    tools = {name: info.fn for name, info in app._tool_manager._tools.items()}

    # event_type filter → only that RuntimeEvent
    results = tools["query_events"](event_type="sensor_anomaly", limit=100)
    assert len(results) == 1
    assert results[0]["event_type"] == "sensor_anomaly"
    assert results[0]["record_type"] == "runtime_event"

    # action filter → only Decisions
    results = tools["query_events"](action="allow", limit=100)
    assert len(results) == 1
    assert results[0]["action"] == "allow"
    assert results[0]["record_type"] == "decision"

    # No filter → all 4 entries, mixed record_types present
    results = tools["query_events"](limit=100)
    types = {r["record_type"] for r in results}
    assert types == {"decision", "runtime_event"}
    assert len(results) == 4
```

- [ ] **Step 5.2: Run test, verify failure**

Run: `pytest tests/test_runtime_event.py::test_mcp_query_events_filters_by_event_type -v`
Expected: FAIL — `event_type` kwarg not accepted by `query_events`, or `record_type` missing from summary.

If the failure is about the `_tool_manager._tools` access pattern, this is a FastMCP internal API. Verify by inspecting `kernel/mcp/tools.py` how tools are registered. Adjust the test access path if needed (the rest of the test logic is independent).

- [ ] **Step 5.3: Extend EventSummary and SearchHit schemas**

Modify `kernel/mcp/schemas.py`. Replace the existing `EventSummary` class with:

```python
class EventSummary(BaseModel):
    id: int
    timestamp_iso: str
    record_type: Literal["decision", "runtime_event"] = "decision"
    action: str | None = None
    threat_level: str | None = None
    event_type: str | None = None
    source: str | None = None
    sig_valid: bool | None = None
```

Replace the existing `SearchHitOut` class (at the bottom of the file) with:

```python
class SearchHitOut(BaseModel):
    event_id: int
    timestamp_iso: str
    record_type: Literal["decision", "runtime_event"] = "decision"
    action: str | None = None
    event_type: str | None = None
    source: str | None = None
    sig_valid: bool | None
    snippet: str
```

- [ ] **Step 5.4: Update _summary() and query_events in tools.py**

Modify `kernel/mcp/tools.py`. Replace the `_summary` helper:

```python
def _summary(ev: dict, sig_valid: bool | None) -> dict:
    record_type = ev.get("record_type", "decision")
    return {
        "id": ev.get("chain_index", -1),
        "timestamp_iso": ev.get("timestamp_iso", ""),
        "record_type": record_type,
        "action": ev.get("action") if record_type == "decision" else None,
        "threat_level": ev.get("threat_level") if record_type == "decision" else None,
        "event_type": ev.get("event_type") if record_type == "runtime_event" else None,
        "source": ev.get("source") if record_type == "runtime_event" else None,
        "sig_valid": sig_valid,
    }
```

Replace the `query_events` tool decorator + function with:

```python
    @app.tool(description="Query audit events (Decisions + RuntimeEvents) with field-aware filters.")
    def query_events(
        start_time: str | None = None,
        end_time: str | None = None,
        action: str | None = None,
        threat_level: str | None = None,
        event_type: str | None = None,
        source: str | None = None,
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
            event_type=event_type,
            source=source,
            limit=limit,
        )
        return [
            _summary(ev, store.verify_event(ev.get("chain_index", -1)))
            for ev in events
        ]
```

Next, plumb `record_type`/`event_type`/`source` through the `search_events` tool's output. This requires extending the `SearchHit` dataclass and its populator in `AuditChainStore.search()`.

Modify `kernel/audit/store.py`. Replace the `SearchHit` dataclass with:

```python
@dataclass
class SearchHit:
    event_id: int
    timestamp_iso: str
    record_type: str
    action: str | None
    event_type: str | None
    source: str | None
    sig_valid: bool | None
    snippet: str
```

Then update `AuditChainStore.search()` (the `results.append(...)` block) to:

```python
            record_type = ev.get("record_type", "decision")
            results.append(SearchHit(
                event_id=ev.get("chain_index", -1),
                timestamp_iso=ev.get("timestamp_iso", ""),
                record_type=record_type,
                action=ev.get("action") if record_type == "decision" else None,
                event_type=ev.get("event_type") if record_type == "runtime_event" else None,
                source=ev.get("source") if record_type == "runtime_event" else None,
                sig_valid=self.verify_event(ev.get("chain_index", -1)),
                snippet=snippet,
            ))
```

Then go back to `kernel/mcp/tools.py search_events` and replace the return statement:

```python
        return [
            {
                "event_id": h.event_id,
                "timestamp_iso": h.timestamp_iso,
                "record_type": h.record_type,
                "action": h.action,
                "event_type": h.event_type,
                "source": h.source,
                "sig_valid": h.sig_valid,
                "snippet": h.snippet,
            }
            for h in hits
        ]
```

- [ ] **Step 5.5: Run the MCP integration test, verify pass**

Run: `pytest tests/test_runtime_event.py::test_mcp_query_events_filters_by_event_type -v`
Expected: PASS.

If FastMCP's internal API (`app._tool_manager._tools`) differs in your version, adapt the test's tool-lookup mechanism. The implementation under test is correct regardless.

- [ ] **Step 5.6: Run all existing MCP tests for regressions**

Run: `pytest tests/mcp/ -v`
Expected: all existing MCP tests still pass. They may have called `_summary()` directly or asserted EventSummary field counts — those assertions may need updating.

If any MCP test fails: inspect the failure. Most likely cause is a hard-coded assertion like `assert summary == {"id": ..., "action": ..., "threat_level": ..., "sig_valid": ...}` that no longer matches because we added fields. Update the assertion to include the new fields (or use partial assertion like `summary["id"] == ...` and `summary["action"] == ...`).

- [ ] **Step 5.7: Run full regression**

Run: `pytest -q`
Expected: ~192 + 9 + 4 + 1 = ~206 PASS, 0 fail.

- [ ] **Step 5.8: Run ruff**

Run: `ruff check kernel/mcp/ kernel/audit/store.py tests/test_runtime_event.py`
Expected: clean.

- [ ] **Step 5.9: Commit Task 5**

```bash
git add kernel/mcp/schemas.py kernel/mcp/tools.py kernel/audit/store.py tests/test_runtime_event.py
git commit -m "MCP: query_events accepts event_type/source filters; record-type-aware summaries"
```

---

## Task 6: Docs + CHANGELOG

**Files:**
- Modify: `docs/architecture.md`
- Modify: `CHANGELOG.md`

No tests — documentation only.

- [ ] **Step 6.0: Read docs/architecture.md to confirm structure (check before assume)**

Open `docs/architecture.md` and verify:
- The file exists (Step 6.1 assumes it does).
- There is no existing section that would conflict with "Upstream Evidence Events" (e.g., an Events / Audit Chain section that already documents this).
- The Markdown heading hierarchy (top-level `#` vs section-level `##` vs subsection `###`) — the new section must match the existing depth convention.
- The end of the file: are there trailing newlines, a "## Future Work" section that should come AFTER the new section, etc.?

If `docs/architecture.md` does NOT exist: create it with a minimal top-level title `# kernel — Architecture` and then proceed.

If there is already an Events-related section: extend it instead of appending a new section — link the existing content with the new RuntimeEvent material rather than duplicating.

- [ ] **Step 6.1: Add "Upstream Evidence Events" section to docs/architecture.md**

Modify `docs/architecture.md`. Append at the end of the file:

```markdown

## Upstream Evidence Events

`RuntimeEvent` is a tipli kayıt türü ki **dış sistemlerden** (sensor monitor, guard middleware, external policy adapter) gelen kanıt event'lerini audit chain'e imzalı olarak yazar. Decision'lardan farkı:

- **Decision** kernel'in karar grafiğinden çıkar ("Şunu yaptım") — kontrollü.
- **RuntimeEvent** dış kaynaktan gelir ("Şunu gözlemledim") — kontrol edilemez.

Her ikisi **aynı Ed25519 imza şeması, aynı SHA-256 hash-link, aynı `chain_index` counter** ile aynı JSONL dosyasına yazılır. Discriminator olarak RuntimeEvent kayıtlarında `record_type: "runtime_event"` field'ı bulunur; Decision'lar bu field'a sahip değildir (geriye uyumluluk).

**Kullanım senaryoları:**
- Sensor anomaly raporu (örn. `event_type="sensor_anomaly"`, `source="lidar_monitor"`)
- External guard middleware downgrade'i (`event_type="guardrail_downgrade"`, `source="kinematic_guard"`)
- Policy adapter ihlal raporu (`event_type="policy_violation"`)

**Karma zincir doğrulama:** `verify_chain()` tip-agnostiktir; RuntimeEvent ve Decision interleaved bir zinciri linear scan ile doğrular. `chain_index` her iki tip arasında **tek bir monotonik sıra** oluşturur — ayrı sayaçlar yoktur.

**Asimetrik koruma:** RuntimeEvent dış sistemden geldiği için `payload` 64KB ile sınırlıdır (`PayloadTooLargeError`). Decision tarafında böyle bir limit yoktur çünkü Decision'lar kernel'in kontrollü policy engine'inden çıkar.

**API:**
```python
from shared.schemas import RuntimeEvent
from services.decision.audit_chain import append_runtime_event

event = RuntimeEvent(
    event_type="sensor_anomaly",
    source="lidar_monitor",
    source_id="lidar-front-01",
    timestamp_iso="2026-05-20T12:00:00+00:00",
    payload={"distance_m": 4.2, "object_class": "vehicle"},
)
signed = append_runtime_event(event, chain_path, signing_key, policy_version_id="p_v1")
```

MCP `query_events` tool'u `event_type` ve `source` parametreleri ile RuntimeEvent'leri filtreler; `action` ve `threat_level` parametreleri Decision'ları filtreler.
```

- [ ] **Step 6.2: Update CHANGELOG.md [Unreleased]**

Modify `CHANGELOG.md`. Find the line `## [Unreleased]` and the empty section beneath it. Replace with:

```markdown
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
```

- [ ] **Step 6.3: Visual review the changes**

Open `docs/architecture.md` and confirm the new section renders correctly (no broken Markdown).
Open `CHANGELOG.md` and confirm the [Unreleased] section follows the existing style.

- [ ] **Step 6.4: Commit Task 6**

```bash
git add docs/architecture.md CHANGELOG.md
git commit -m "docs: RuntimeEvent in architecture.md + CHANGELOG [Unreleased]"
```

---

## Task 7: Final verification (no commit — just checks)

This task confirms the whole system stands together before reporting back to the user.

- [ ] **Step 7.1: Full pytest run with verbose output**

Run: `pytest -v`
Expected: ~206 PASS, 0 fail. Note exact numbers for the final report.

- [ ] **Step 7.2: Full ruff check**

Run: `ruff check .`
Expected: clean. Compare against the baseline noted in Step 0.3 — no new warnings.

- [ ] **Step 7.3: Confirm commit graph looks right**

Run: `git log --oneline main..HEAD`
Expected: 6 commits, one per task (Tasks 1–6).

- [ ] **Step 7.4: Confirm working tree is clean**

Run: `git status`
Expected: clean working tree, nothing to commit (or only the pre-existing uncommitted style changes from before this work — those are NOT part of this branch's work).

If anything to do with RuntimeEvent is uncommitted: investigate which task missed it and either add to the corresponding commit (via `git add` + amend ONLY if the prior commit is the immediate predecessor and not yet pushed) or create a Task-7 fixup commit.

- [ ] **Step 7.5: Produce final report for the user**

Write a single message back containing:
- Baseline test count (from Step 0.2)
- Final test count
- New tests added (10 total: 9 from spec + 1 alias smoke test)
- Files changed (8 files per spec §10)
- ruff status
- Commit list (6 commits)
- Anything unexpected encountered

Stop. Do not push. Do not commit anything further. Wait for user review.

---

## Spec coverage cross-check (self-review)

| Spec section | Covered by task |
|---|---|
| §2 Out of scope (no Decision change, no new MCP tool, no ROS2, no adapter) | Maintained throughout — Decision schema untouched; no new `@app.tool` |
| §3 RuntimeEvent vs Decision discriminator | Task 1 (`record_type` Literal) |
| §4 Single shared chain_index | Task 2 (`append_runtime_event` reads last entry); Task 3 tests (`test_mixed_chain_decision_then_runtime`, `test_prev_hash_integrity_mixed`) |
| §5 Schema with PayloadTooLargeError + source_id constraints | Task 1 |
| §6 append_runtime_event behavior contract incl. payload size + caller-overwrite | Task 2 (`test_caller_provided_chain_fields_are_overwritten`) + Task 1 (size validation upstream) |
| §7 Verification polymorphic + verify_runtime_event alias | Task 3 |
| §8.1 AuditChainStore field-aware filter | Task 4 |
| §8.2 query_events new params | Task 5 |
| §8.3 EventSummary with Literal record_type | Task 5 |
| §8.4 search_events SearchHit record_type | Task 5 |
| §9 Test plan (9 tests) | Tasks 1–5 |
| §10 File list (8 files) | Tasks 1–6 (matches) |
| §13 Done definition | Task 7 final verification |

## Commit boundaries summary (for the user)

| Commit | Scope | Tests added cumulatively |
|---|---|---|
| 1 | Schema + PayloadTooLargeError + source_id constraints | 3 |
| 2 | `append_runtime_event()` + caller-overwrite contract | 5 |
| 3 | Mixed chain verification + `verify_runtime_event` alias | 9 (+1 alias smoke) |
| 4 | Field-aware `AuditChainStore.filter()` | 13 |
| 5 | MCP integration (schemas + tools) | 14 |
| 6 | Docs + CHANGELOG | 14 |

## pytest run points (for the user)

- After every `*_test.py` change inside a task (granular)
- Full `pytest -q` regression at the end of each task (Tasks 1–5)
- Final `pytest -v` at Task 7 Step 1
