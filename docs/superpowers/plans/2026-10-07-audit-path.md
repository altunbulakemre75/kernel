# v0.3.0 Part A — One Verifiable Audit Chain: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every decision from `run_graph()` is durably appended, under an inter-process lock, to the same signed JSONL chain that `kyvern-verify`, `kyvern-report` and `kyvern-mcp` read; an unrecordable decision raises instead of being returned; every entry names the key that signed it, and verifiers accept several keys.

**Architecture:** A new `ChainWriter` (`services/decision/chain_writer.py`) is the only code that appends to the chain: lock → read tail → sign → write → fsync. `run_graph`'s `finalize` node and `append_runtime_event()` both delegate to it; Postgres recording is removed. `sign_decision()` embeds a `key_id`; a `Keyring` lets the verifiers pick the right public key per entry.

**Tech Stack:** Python 3.10–3.13, `cryptography` (Ed25519), `filelock`, pytest/pytest-asyncio, ruff. Local shell is PowerShell on Windows; CI is Linux.

**Spec:** `docs/superpowers/specs/2026-10-07-audit-path-design.md`
**Branch:** `feat/audit-path` (from `main` at `67788ce`; spec commit `928b32b`).

**Test count:** 221 passed, 3 skipped before this work. Each task states the expected total after it.

**`<scratchpad>`** means `C:\Users\altun\AppData\Local\Temp\claude\C--Users-altun-Desktop-Yeni-klas-r-kernel\e0dd28f8-16c4-4728-a9f9-fe35f6b37298\scratchpad`, a directory outside the repo for one-off files.

**Run tests with:** `python -m pytest -q -p no:cacheprovider` (add a path to narrow). **Lint with:** `python -m ruff check .`

---

## File map

| File | Responsibility | Change |
|---|---|---|
| `tests/conftest.py` | Shared fixtures | Autouse `isolated_home` fixture: `Path.home()` → temp dir, `KYVERN_CHAIN_PATH` unset |
| `shared/paths.py` | Per-user locations | Add `CHAIN_PATH_ENV`, `default_chain_path()` |
| `services/decision/audit_chain.py` | Signing and verification | `key_id()`, `Keyring`, key-aware `verify_decision`/`verify_chain`, `describe_chain_failure()`; `sign_decision` embeds `key_id`; `append_runtime_event` delegates to `ChainWriter` |
| `services/decision/chain_writer.py` | **New.** The only appender | `AuditWriteError`, `ChainWriter` (`append`, `open`) |
| `services/decision/schemas.py`, `shared/schemas.py` | Record models | `key_id: str \| None = None` on `Decision` and `RuntimeEvent` |
| `services/decision/llm_graph.py` | Live pipeline | `finalize` appends through `ChainWriter`; Postgres code removed; `run_graph(chain_path=...)` |
| `services/decision/threat_graph.py` | Sync wrapper | `decide_full(chain_path=...)` |
| `cli/kyvern_verify.py`, `cli/kyvern_report.py` | Offline verifiers | Repeatable `--pubkey` → `Keyring`; failure reason; key ids |
| `kyvern/audit/store.py`, `kyvern/mcp/server.py` | MCP read side | `Keyring`; repeatable `--pubkey`; chain default from `default_chain_path()`; reason in `first_break` |
| `requirements.txt` | Dependencies | Add `filelock>=3.12`; remove `asyncpg` |
| `docs/threat-model.md`, `docs/architecture.md`, `README.md`, `CHANGELOG.md` | Docs | Recording guarantees, rotation procedure, breaking changes |

---

### Task 1: Keep every test away from the real home directory

**Files:**
- Modify: `tests/conftest.py`
- Test: `tests/test_paths.py`

- [ ] **Step 1: Record the real `~/.kyvern` fingerprint (acceptance check for the whole plan)**

```powershell
Get-ChildItem "$HOME\.kyvern" -Recurse -File | ForEach-Object { "{0} {1}" -f $_.FullName.Substring($HOME.Length), (Get-FileHash $_.FullName -Algorithm SHA256).Hash } | Sort-Object
```

Expected today: `\.kyvern\keys\signing.key …` and `\.kyvern\keys\signing.pub 42190995279E05C0F27599C642395802FC79AA71DFD938024155A17077CDBE9C`. Keep this output; Task 9 compares against it.

- [ ] **Step 2: Write the failing test**

Append to `tests/test_paths.py`:

```python
def test_suite_runs_with_an_isolated_home(isolated_home):
    assert Path.home() == isolated_home
    assert "KYVERN_CHAIN_PATH" not in os.environ
```

and add `import os` at the top of the file (above `from pathlib import Path`).

- [ ] **Step 3: Run it to verify it fails**

Run: `python -m pytest -q -p no:cacheprovider tests/test_paths.py::test_suite_runs_with_an_isolated_home`
Expected: ERROR — `fixture 'isolated_home' not found`.

- [ ] **Step 4: Add the autouse fixture**

In `tests/conftest.py`, add `from pathlib import Path` to the imports (after `from datetime import datetime, timezone`), and add this block right after the `_now_iso` helper:

```python
# ══════════════════════════════════════════════════════════════════════════════
# Isolation from the developer's real home directory
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def isolated_home(tmp_path_factory, monkeypatch) -> Path:
    """Point Path.home() at a fresh directory for every test.

    run_graph() and ChainWriter.open() create the signing key under ~/.kyvern and
    append to ~/.kyvern/chain.jsonl; no test may touch the developer's real ones.
    """
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    monkeypatch.delenv("KYVERN_CHAIN_PATH", raising=False)
    return home
```

- [ ] **Step 5: Run the full suite**

Run: `python -m pytest -q -p no:cacheprovider`
Expected: `222 passed, 3 skipped`.

- [ ] **Step 6: Lint and commit**

Run: `python -m ruff check .` → `All checks passed!`

```bash
git add tests/conftest.py tests/test_paths.py
git commit -m "test: run every test with an isolated home directory"
```

---

### Task 2: `key_id`, `Keyring` and key-aware verification

**Files:**
- Modify: `services/decision/audit_chain.py`
- Modify: `services/decision/schemas.py:71-77`, `shared/schemas.py:35-40`
- Test: `tests/decision/test_audit_chain.py`

- [ ] **Step 1: Write the failing tests**

At the top of `tests/decision/test_audit_chain.py`, add `import base64` above `import copy`, and extend the existing `from services.decision.audit_chain import (...)` block so it reads:

```python
from services.decision.audit_chain import (
    Keyring,
    canonical_json,
    describe_chain_failure,
    key_id,
    sha256_hex,
    sign_decision,
    verify_chain,
    verify_decision,
)
```

Then append to the end of the file:

```python
# ── key_id and Keyring ────────────────────────────────────────────────────────

def _chain(sample_decision, keys):
    chain, prev = [], None
    for i, key in enumerate(keys):
        signed = sign_decision(dict(sample_decision, chain_index=i), prev_hash=prev, signing_key=key)
        chain.append(signed)
        prev = signed["payload_hash"]
    return chain


def test_key_id_is_embedded_and_signed(sample_decision):
    key = ed25519.Ed25519PrivateKey.generate()
    signed = sign_decision(sample_decision, prev_hash=None, signing_key=key)
    assert signed["key_id"] == key_id(key.public_key())
    assert len(signed["key_id"]) == 16
    assert verify_decision(signed, key.public_key()) is True
    assert verify_decision(dict(signed, key_id="0" * 16), key.public_key()) is False


def test_keyring_verifies_a_chain_signed_by_two_keys(sample_decision):
    k1, k2 = ed25519.Ed25519PrivateKey.generate(), ed25519.Ed25519PrivateKey.generate()
    chain = _chain(sample_decision, [k1, k1, k2])
    assert verify_chain(chain, Keyring([k1.public_key(), k2.public_key()])) == (True, None)


def test_missing_key_is_reported_as_unknown(sample_decision):
    k1, k2 = ed25519.Ed25519PrivateKey.generate(), ed25519.Ed25519PrivateKey.generate()
    chain = _chain(sample_decision, [k1, k1, k2])
    only_k1 = Keyring([k1.public_key()])
    assert verify_chain(chain, only_k1) == (False, 2)
    assert verify_chain(chain, k1.public_key()) == (False, 2)
    assert describe_chain_failure(chain, 2, only_k1) == (
        f"signed by unknown key {key_id(k2.public_key())}"
    )


def test_record_without_key_id_still_verifies(sample_decision):
    key = ed25519.Ed25519PrivateKey.generate()
    legacy = dict(sample_decision, prev_hash=None, chain_index=0)  # signed the pre-0.3.0 way
    payload = canonical_json(legacy)
    legacy["payload_hash"] = sha256_hex(payload)
    legacy["signature"] = base64.b64encode(key.sign(payload)).decode()
    other = ed25519.Ed25519PrivateKey.generate().public_key()
    assert verify_decision(legacy, key.public_key()) is True
    assert verify_decision(legacy, Keyring([other, key.public_key()])) is True
    assert verify_decision(legacy, Keyring([other])) is False


def test_describe_chain_failure_names_each_reason(sample_decision):
    key = ed25519.Ed25519PrivateKey.generate()
    keys = Keyring([key.public_key()])

    gap = _chain(sample_decision, [key, key, key])
    gap[1]["chain_index"] = 5
    assert describe_chain_failure(gap, 1, keys).startswith("chain_index gap")

    link = _chain(sample_decision, [key, key, key])
    link[1]["prev_hash"] = "00" * 32
    assert describe_chain_failure(link, 1, keys) == "broken prev_hash link"

    tampered = _chain(sample_decision, [key, key, key])
    tampered[1]["reasoning"] = "rewritten"
    assert describe_chain_failure(tampered, 1, keys) == "bad signature"
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python -m pytest -q -p no:cacheprovider tests/decision/test_audit_chain.py`
Expected: collection ERROR — `ImportError: cannot import name 'Keyring'`.

- [ ] **Step 3: Implement**

In `services/decision/audit_chain.py`:

(a) Extend the imports at the top:

```python
import base64
import hashlib
import json
import os
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any
```

(b) Insert right after `load_or_create_keypair()`:

```python
def key_id(public_key: ed25519.Ed25519PublicKey) -> str:
    """First 16 hex chars of SHA-256 over the raw 32-byte public key."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:16]


class Keyring:
    """Public keys a verifier trusts, looked up by the key_id stored in each record."""

    def __init__(self, public_keys: Iterable[ed25519.Ed25519PublicKey]) -> None:
        self._keys = {key_id(k): k for k in public_keys}

    @classmethod
    def from_pem_files(cls, paths: Iterable[str | Path]) -> "Keyring":
        return cls(serialization.load_pem_public_key(Path(p).read_bytes()) for p in paths)

    def get(self, kid: str) -> ed25519.Ed25519PublicKey | None:
        return self._keys.get(kid)

    def ids(self) -> list[str]:
        return list(self._keys)

    def __iter__(self) -> Iterator[ed25519.Ed25519PublicKey]:
        return iter(self._keys.values())

    def __len__(self) -> int:
        return len(self._keys)


PublicKeys = ed25519.Ed25519PublicKey | Keyring


def _candidate_keys(record: dict[str, Any], keys: PublicKeys) -> list[ed25519.Ed25519PublicKey]:
    """Keys allowed to have signed `record`. Records from before key_id existed may be
    signed by any trusted key; records with a key_id only by that key."""
    rid = record.get("key_id")
    if isinstance(keys, Keyring):
        if rid is None:
            return list(keys)
        key = keys.get(rid)
        return [key] if key is not None else []
    if rid is None or rid == key_id(keys):
        return [keys]
    return []
```

(c) In `sign_decision()`, add one line before `payload = canonical_json(signed_decision)`:

```python
    signed_decision["key_id"] = key_id(signing_key.public_key())
```

and add to its docstring: `It also sets key_id, which is covered by the signature.`

(d) Replace `verify_decision()` with:

```python
def verify_decision(decision: dict[str, Any], public_key: PublicKeys) -> bool:
    """Verify an audit chain entry's signature.

    Polymorphic: works for Decision dicts AND RuntimeEvent dicts. `public_key` is a
    single Ed25519 public key or a Keyring; see _candidate_keys for key selection.
    """
    try:
        signature = decision.get("signature")
        if not signature:
            return False

        payload = canonical_json(decision)
        if decision.get("payload_hash") != sha256_hex(payload):
            return False

        sig_bytes = base64.b64decode(signature)
        for key in _candidate_keys(decision, public_key):
            try:
                key.verify(sig_bytes, payload)
                return True
            except InvalidSignature:
                continue
        return False
    except (ValueError, TypeError):
        return False
```

(e) In `verify_chain()` change only the signature line to `def verify_chain(decisions: list[dict[str, Any]], public_key: PublicKeys) -> tuple[bool, int | None]:` and add to its docstring: `public_key may be a Keyring for chains signed by several keys.`

(f) Insert right after `verify_chain()`:

```python
def describe_chain_failure(
    records: list[dict[str, Any]], index: int, public_key: PublicKeys
) -> str:
    """Explain why records[index] failed verify_chain()."""
    record = records[index]
    expected_index = records[0].get("chain_index", 0) + index
    if record.get("chain_index") != expected_index:
        return f"chain_index gap: expected {expected_index}, found {record.get('chain_index')}"
    expected_prev = None if index == 0 else records[index - 1].get("payload_hash")
    if record.get("prev_hash") != expected_prev:
        return "broken prev_hash link"
    rid = record.get("key_id")
    if rid is not None and not _candidate_keys(record, public_key):
        return f"signed by unknown key {rid}"
    return "bad signature"
```

(g) In `verify_decision_against_policy()` change the type of `public_key` to `PublicKeys`.

(h) In `services/decision/schemas.py`, add after `payload_hash: str | None = None` in `Decision`:

```python
    key_id: str | None = None     # which key signed it (see audit_chain.key_id)
```

and in `shared/schemas.py`, add after `payload_hash: str | None = None` in `RuntimeEvent`:

```python
    key_id: str | None = None
```

- [ ] **Step 4: Run the tests**

Run: `python -m pytest -q -p no:cacheprovider tests/decision/test_audit_chain.py`
Expected: all pass (7 existing + 5 new).

Run: `python -m pytest -q -p no:cacheprovider`
Expected: `227 passed, 3 skipped`.

- [ ] **Step 5: Lint and commit**

Run: `python -m ruff check .` → `All checks passed!` (if `I001`/`UP` findings appear, run `python -m ruff check . --fix` and re-run).

```bash
git add services/decision/audit_chain.py services/decision/schemas.py shared/schemas.py tests/decision/test_audit_chain.py
git commit -m "feat: sign a key_id into every chain entry and verify with a keyring"
```

---

### Task 3: `ChainWriter` — locked, durable appends

**Files:**
- Create: `services/decision/chain_writer.py`
- Modify: `shared/paths.py`, `requirements.txt`
- Test: create `tests/decision/test_chain_writer.py`; extend `tests/test_paths.py`

- [ ] **Step 1: Add the dependency**

In `requirements.txt`, add a line after `cryptography>=42.0.0`:

```
filelock>=3.12.0  # inter-process lock for appending to the audit chain
```

Run: `python -c "import filelock; print(filelock.__version__)"` → a version ≥ 3.12 (3.25.2 on the dev machine).

- [ ] **Step 2: Write the failing tests for `default_chain_path`**

Append to `tests/test_paths.py`:

```python
def test_default_chain_path_lives_in_kyvern_home(isolated_home):
    from shared.paths import default_chain_path

    assert default_chain_path() == isolated_home / ".kyvern" / "chain.jsonl"


def test_default_chain_path_honours_the_env_override(tmp_path, monkeypatch):
    from shared.paths import default_chain_path

    monkeypatch.setenv("KYVERN_CHAIN_PATH", str(tmp_path / "elsewhere.jsonl"))
    assert default_chain_path() == tmp_path / "elsewhere.jsonl"
```

- [ ] **Step 3: Write the failing writer tests**

Create `tests/decision/test_chain_writer.py`:

```python
"""ChainWriter: the only code that appends to the audit chain."""
from __future__ import annotations

import json
import multiprocessing
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from filelock import FileLock

from services.decision import chain_writer
from services.decision.audit_chain import key_id, verify_chain, verify_decision
from services.decision.chain_writer import AuditWriteError, ChainWriter


@pytest.fixture
def signing_key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


def _lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_first_and_second_entries_link(tmp_path, signing_key):
    chain = tmp_path / "nested" / "chain.jsonl"  # parent directory is created on demand
    writer = ChainWriter(chain, signing_key)
    first = writer.append({"n": 1})
    second = writer.append({"n": 2})
    assert (first["chain_index"], first["prev_hash"]) == (0, None)
    assert (second["chain_index"], second["prev_hash"]) == (1, first["payload_hash"])
    assert _lines(chain) == [first, second]


def test_caller_chain_fields_are_replaced(tmp_path, signing_key):
    signed = ChainWriter(tmp_path / "chain.jsonl", signing_key).append({
        "n": 1, "chain_index": 99, "prev_hash": "ff" * 32,
        "payload_hash": "x", "signature": "y", "key_id": "evil",
    })
    assert (signed["chain_index"], signed["prev_hash"]) == (0, None)
    assert signed["key_id"] == key_id(signing_key.public_key())
    assert verify_decision(signed, signing_key.public_key()) is True


def test_each_append_is_fsynced(tmp_path, signing_key, monkeypatch):
    calls = []
    real_fsync = os.fsync

    def counting_fsync(fd):
        calls.append(fd)
        real_fsync(fd)

    monkeypatch.setattr(chain_writer.os, "fsync", counting_fsync)
    writer = ChainWriter(tmp_path / "chain.jsonl", signing_key)
    writer.append({"n": 1})
    writer.append({"n": 2})
    assert len(calls) == 2


def test_corrupt_tail_is_refused_and_file_left_untouched(tmp_path, signing_key):
    chain = tmp_path / "chain.jsonl"
    writer = ChainWriter(chain, signing_key)
    writer.append({"n": 1})
    with open(chain, "ab") as f:
        f.write(b'{"chain_index": 1, "payload_')  # torn write: no newline, no closing brace
    before = chain.read_bytes()
    with pytest.raises(AuditWriteError, match="corrupt"):
        writer.append({"n": 2})
    assert chain.read_bytes() == before


def test_append_times_out_while_another_writer_holds_the_lock(tmp_path, signing_key):
    chain = tmp_path / "chain.jsonl"
    with FileLock(str(chain) + ".lock"):
        with pytest.raises(AuditWriteError):
            ChainWriter(chain, signing_key, lock_timeout_s=0.2).append({"n": 1})
    assert not chain.exists()


def _append_many(chain_path: str, key_pem: bytes, worker: int, count: int) -> None:
    key = serialization.load_pem_private_key(key_pem, password=None)
    writer = ChainWriter(Path(chain_path), key)
    for i in range(count):
        writer.append({"worker": worker, "n": i})


def test_concurrent_processes_keep_one_unbroken_chain(tmp_path, signing_key):
    chain = tmp_path / "chain.jsonl"
    key_pem = signing_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    ctx = multiprocessing.get_context("spawn")
    procs = [ctx.Process(target=_append_many, args=(str(chain), key_pem, w, 25)) for w in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=180)
    assert [p.exitcode for p in procs] == [0, 0, 0, 0]
    entries = _lines(chain)
    assert [e["chain_index"] for e in entries] == list(range(100))
    assert verify_chain(entries, signing_key.public_key()) == (True, None)


def test_open_refuses_to_mint_a_key_for_an_existing_chain(tmp_path, isolated_home, signing_key):
    chain = tmp_path / "chain.jsonl"
    ChainWriter(chain, signing_key).append({"n": 1})
    with pytest.raises(AuditWriteError, match="refusing to create a new signing key"):
        ChainWriter.open(chain)
    assert not (isolated_home / ".kyvern" / "keys" / "signing.key").exists()


def test_open_creates_a_key_for_a_new_chain(tmp_path, isolated_home):
    writer = ChainWriter.open(tmp_path / "chain.jsonl")
    assert (isolated_home / ".kyvern" / "keys" / "signing.key").is_file()
    assert writer.append({"n": 1})["chain_index"] == 0


def test_open_without_a_path_uses_the_env_override(tmp_path, monkeypatch):
    target = tmp_path / "env-chain.jsonl"
    monkeypatch.setenv("KYVERN_CHAIN_PATH", str(target))
    ChainWriter.open().append({"n": 1})
    assert len(_lines(target)) == 1
```

- [ ] **Step 4: Run them to verify they fail**

Run: `python -m pytest -q -p no:cacheprovider tests/decision/test_chain_writer.py tests/test_paths.py`
Expected: ERROR collecting `test_chain_writer.py` (`No module named 'services.decision.chain_writer'`) and two failures in `test_paths.py` (`cannot import name 'default_chain_path'`).

- [ ] **Step 5: Add `default_chain_path()`**

In `shared/paths.py`, add `import os` above `from pathlib import Path`, add after `LEGACY_HOME_DIR_NAME`:

```python
CHAIN_PATH_ENV = "KYVERN_CHAIN_PATH"
```

and append:

```python
def default_chain_path() -> Path:
    """The audit chain file used when none is given: $KYVERN_CHAIN_PATH, else ~/.kyvern/chain.jsonl."""
    override = os.environ.get(CHAIN_PATH_ENV)
    return Path(override) if override else kyvern_home() / "chain.jsonl"
```

- [ ] **Step 6: Create `services/decision/chain_writer.py`**

```python
"""ChainWriter — the only code that appends to the audit chain.

Each append holds an inter-process file lock while it reads the last entry,
signs the new one and writes it, then fsyncs before returning. Several processes
on one host can therefore share a chain without forking it. Anything that goes
wrong is raised as AuditWriteError: a record either is durably in the chain or
the caller hears about it.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ed25519
from filelock import FileLock

from services.decision.audit_chain import load_or_create_keypair, sign_decision
from shared.paths import default_chain_path, kyvern_home

_CHAIN_FIELDS = ("signature", "payload_hash", "key_id", "prev_hash", "chain_index")


class AuditWriteError(RuntimeError):
    """A record could not be durably appended to the audit chain."""


def _read_tail(path: Path) -> tuple[bytes | None, bool]:
    """Return (last non-empty line, file ends with a newline), reading from the end."""
    if not path.exists():
        return None, True
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        end = f.tell()
        if end == 0:
            return None, True
        f.seek(end - 1)
        ends_with_newline = f.read(1) == b"\n"
        pos, buf = end, b""
        while pos > 0:
            step = min(4096, pos)
            pos -= step
            f.seek(pos)
            buf = f.read(step) + buf
            stripped = buf.rstrip()
            if b"\n" in stripped:
                return stripped.rsplit(b"\n", 1)[1], ends_with_newline
        stripped = buf.rstrip()
        return (stripped or None), ends_with_newline


def _last_entry(path: Path) -> dict[str, Any] | None:
    line, ends_with_newline = _read_tail(path)
    if line is None:
        return None
    try:
        entry = json.loads(line)
    except ValueError:
        entry = None
    if (
        not ends_with_newline
        or not isinstance(entry, dict)
        or "payload_hash" not in entry
        or not isinstance(entry.get("chain_index"), int)
    ):
        raise AuditWriteError(
            f"chain tail is corrupt in {path} (last write may be incomplete); "
            "run kyvern-verify before appending"
        )
    return entry


class ChainWriter:
    def __init__(
        self,
        chain_path: Path,
        signing_key: ed25519.Ed25519PrivateKey,
        lock_timeout_s: float = 10.0,
    ) -> None:
        self._chain_path = Path(chain_path)
        self._signing_key = signing_key
        self._lock_timeout_s = lock_timeout_s

    @classmethod
    def open(cls, chain_path: Path | None = None) -> ChainWriter:
        """Writer for `chain_path` (default: default_chain_path()) signing with ~/.kyvern's key.

        Never creates a new signing key next to a chain that already has entries:
        that would silently switch keys mid-chain.
        """
        try:
            path = Path(chain_path) if chain_path is not None else default_chain_path()
            key_file = kyvern_home() / "keys" / "signing.key"
            if not key_file.exists() and _read_tail(path)[0] is not None:
                raise AuditWriteError(
                    f"refusing to create a new signing key for an existing chain: "
                    f"{key_file} is missing but {path} already has entries"
                )
            return cls(path, load_or_create_keypair())
        except AuditWriteError:
            raise
        except Exception as exc:
            raise AuditWriteError(f"could not open the audit chain: {exc}") from exc

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        """Sign `record` as the next entry, append it durably, and return the signed dict."""
        try:
            self._chain_path.parent.mkdir(parents=True, exist_ok=True)
            with FileLock(str(self._chain_path) + ".lock", timeout=self._lock_timeout_s):
                return self._append_locked(record)
        except AuditWriteError:
            raise
        except Exception as exc:
            raise AuditWriteError(f"could not append to {self._chain_path}: {exc}") from exc

    def _append_locked(self, record: dict[str, Any]) -> dict[str, Any]:
        last = _last_entry(self._chain_path)
        entry = {k: v for k, v in record.items() if k not in _CHAIN_FIELDS}
        entry["chain_index"] = 0 if last is None else last["chain_index"] + 1
        prev_hash = None if last is None else last["payload_hash"]
        signed = sign_decision(entry, prev_hash=prev_hash, signing_key=self._signing_key)
        line = json.dumps(signed, separators=(",", ":")) + "\n"
        with open(self._chain_path, "a", encoding="utf-8", newline="\n") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
        return signed
```

- [ ] **Step 7: Run the tests**

Run: `python -m pytest -q -p no:cacheprovider tests/decision/test_chain_writer.py tests/test_paths.py`
Expected: all pass (9 writer tests; `test_paths.py` 9 tests).

Run: `python -m pytest -q -p no:cacheprovider`
Expected: `238 passed, 3 skipped`.

- [ ] **Step 8: Lint and commit**

Run: `python -m ruff check .` → `All checks passed!`

```bash
git add services/decision/chain_writer.py shared/paths.py requirements.txt tests/decision/test_chain_writer.py tests/test_paths.py
git commit -m "feat: ChainWriter appends to the audit chain under a file lock and fsyncs"
```

---

### Task 4: RuntimeEvents go through `ChainWriter`

**Files:**
- Modify: `services/decision/audit_chain.py` (`append_runtime_event`)
- Test: `tests/test_runtime_event.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_runtime_event.py`:

```python
def test_append_runtime_event_uses_the_chain_writer(tmp_path: Path, signing_key, public_key):
    from services.decision.audit_chain import append_runtime_event, key_id
    from services.decision.chain_writer import AuditWriteError

    chain_path = tmp_path / "chain.jsonl"
    signed = append_runtime_event(
        RuntimeEvent(**_valid_event_kwargs()), chain_path, signing_key, "p_test"
    )
    assert signed.key_id == key_id(public_key)

    with open(chain_path, "ab") as f:
        f.write(b"{torn")
    with pytest.raises(AuditWriteError, match="corrupt"):
        append_runtime_event(RuntimeEvent(**_valid_event_kwargs()), chain_path, signing_key, "p_test")
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python -m pytest -q -p no:cacheprovider tests/test_runtime_event.py::test_append_runtime_event_uses_the_chain_writer`
Expected: FAIL — the second append does not raise (the old code appends after the torn line).

- [ ] **Step 3: Implement**

Replace the body of `append_runtime_event()` (everything after its docstring) with:

```python
    # Imported here: chain_writer imports this module.
    from services.decision.chain_writer import ChainWriter

    record = event.model_dump()
    record["policy_version_id"] = policy_version_id
    # ChainWriter discards caller-supplied signature/payload_hash/key_id/prev_hash/
    # chain_index, holds the chain lock, checks the tail and fsyncs.
    signed = ChainWriter(Path(chain_path), signing_key).append(record)
    return RuntimeEvent(**signed)
```

and in its docstring replace the sentence about the single-writer assumption, if any, with: `Raises AuditWriteError if the event cannot be appended.`

- [ ] **Step 4: Run the tests**

Run: `python -m pytest -q -p no:cacheprovider tests/test_runtime_event.py tests/audit tests/mcp`
Expected: all pass.

Run: `python -m pytest -q -p no:cacheprovider`
Expected: `239 passed, 3 skipped`.

- [ ] **Step 5: Lint and commit**

Run: `python -m ruff check .` → `All checks passed!`

```bash
git add services/decision/audit_chain.py tests/test_runtime_event.py
git commit -m "feat: append_runtime_event goes through ChainWriter"
```

---

### Task 5: The live pipeline records every decision, or raises

**Files:**
- Modify: `services/decision/llm_graph.py` (module docstring, imports, `GraphState`, `finalize`, `run_graph`)
- Modify: `services/decision/threat_graph.py` (`decide_full`)
- Modify: `requirements.txt` (remove `asyncpg`)
- Test: `tests/decision/test_llm_graph.py`, `tests/decision/test_threat_graph_unification.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/decision/test_llm_graph.py` (add `import json` at the top):

```python
@pytest.mark.asyncio
async def test_run_graph_appends_each_decision_to_the_chain(tmp_path):
    chain = tmp_path / "chain.jsonl"
    rules = load_roe(CONFIG_PATH)
    d1 = await run_graph(_track(), rules, chain_path=chain)
    d2 = await run_graph(_track(track_id="t-2"), rules, chain_path=chain)
    entries = [json.loads(line) for line in chain.read_text(encoding="utf-8").splitlines()]
    assert [e["track_id"] for e in entries] == ["t-graph", "t-2"]
    assert [e["chain_index"] for e in entries] == [0, 1]
    assert d2.prev_hash == d1.payload_hash == entries[0]["payload_hash"]
    assert d1.key_id == entries[0]["key_id"]


@pytest.mark.asyncio
async def test_run_graph_defaults_to_the_kyvern_home_chain(isolated_home):
    await run_graph(_track(), load_roe(CONFIG_PATH))
    chain = isolated_home / ".kyvern" / "chain.jsonl"
    assert len(chain.read_text(encoding="utf-8").splitlines()) == 1


@pytest.mark.asyncio
async def test_run_graph_raises_when_the_decision_cannot_be_recorded(tmp_path):
    from services.decision.chain_writer import AuditWriteError

    chain = tmp_path / "chain.jsonl"
    chain.mkdir()  # a directory where the chain file should be: appending fails
    with pytest.raises(AuditWriteError):
        await run_graph(_track(), load_roe(CONFIG_PATH), chain_path=chain)
```

Append to `tests/decision/test_threat_graph_unification.py`:

```python
def test_decide_full_records_to_the_given_chain(tmp_path):
    chain = tmp_path / "chain.jsonl"
    decision = decide_full(_track(), load_roe(CONFIG_PATH), chain_path=chain)
    assert decision.chain_index == 0
    assert chain.read_text(encoding="utf-8").count("\n") == 1
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python -m pytest -q -p no:cacheprovider tests/decision/test_llm_graph.py tests/decision/test_threat_graph_unification.py`
Expected: 4 failures — `run_graph() got an unexpected keyword argument 'chain_path'` (×2), the home chain file does not exist, `decide_full() got an unexpected keyword argument 'chain_path'`.

- [ ] **Step 3: Implement in `services/decision/llm_graph.py`**

(a) Module docstring line `  5. finalize     — create Decision + (optional) PostgreSQL checkpoint` becomes:

```
  5. finalize     — sign the Decision and append it to the audit chain (raises if it cannot)
```

(b) Imports: add `from pathlib import Path` after `from datetime import datetime, timezone`, and add after the `services.decision.schemas` import block:

```python
from services.decision.chain_writer import ChainWriter
```

(c) `GraphState`: add after `loaded_policy: Any | None = None`:

```python
    chain_path: Path | None = None
```

(d) Replace the whole `finalize` function with:

```python
async def finalize(state: GraphState) -> GraphState:
    """Sign the decision and append it to the audit chain.

    Raises AuditWriteError (from ChainWriter) if the decision cannot be recorded,
    so run_graph() never returns a decision that is not in the chain.
    """
    if state.decision is None:
        return state

    if state.loaded_policy:
        state.decision.policy_version_id = state.loaded_policy.version_id
        state.decision.policy_path = state.loaded_policy.path

    writer = ChainWriter.open(state.chain_path)
    signed = writer.append(state.decision.model_dump(mode="json"))
    state.decision = Decision(**signed)
    return state
```

(e) `run_graph`: add the parameter after `policy_path: str | None = None,`:

```python
    chain_path: Path | str | None = None,
```

change its docstring to:

```python
    """Run the 5-node flow sequentially. Uses StateGraph if LangGraph is installed.

    The decision is appended to the audit chain at `chain_path` (default:
    $KYVERN_CHAIN_PATH, else ~/.kyvern/chain.jsonl). Raises AuditWriteError if it
    cannot be recorded.
    """
```

and add to the `GraphState(...)` constructor call:

```python
        chain_path=Path(chain_path) if chain_path is not None else None,
```

`import os` stays (used by `_llm_enabled`).

- [ ] **Step 4: Implement in `services/decision/threat_graph.py`**

Add `from pathlib import Path` after `from datetime import datetime, timezone`. In `decide_full` add the parameter `chain_path: Path | str | None = None,` after `policy_path: str | None = None,`, add to its docstring `Raises AuditWriteError if the decision cannot be recorded.`, and pass `chain_path=chain_path,` to `run_graph(...)`.

- [ ] **Step 5: Remove `asyncpg`**

Delete the line `asyncpg==0.30.0` from `requirements.txt`. Then:

Run: `git grep -n -i -e asyncpg -e DB_DSN -- . ':!docs/superpowers' ':!CHANGELOG.md'`
Expected: only `docs/architecture.md` lines (fixed in Task 8).

- [ ] **Step 6: Run the tests**

Run: `python -m pytest -q -p no:cacheprovider tests/decision`
Expected: all pass.

Run: `python -m pytest -q -p no:cacheprovider`
Expected: `243 passed, 3 skipped`.

- [ ] **Step 7: Lint and commit**

Run: `python -m ruff check .` → `All checks passed!` (remove any import ruff reports as unused, e.g. `os` is still used; `log` is still used by other nodes).

```bash
git add services/decision/llm_graph.py services/decision/threat_graph.py requirements.txt tests/decision/test_llm_graph.py tests/decision/test_threat_graph_unification.py
git commit -m "feat: run_graph appends every decision to the audit chain and raises if it cannot

Postgres recording (KYVERN_DB_DSN, asyncpg) is removed; the JSONL chain is the
single source of truth."
```

---

### Task 6: `kyvern-verify` and `kyvern-report` take several keys

**Files:**
- Modify: `cli/kyvern_verify.py`, `cli/kyvern_report.py`
- Test: `tests/cli/test_kyvern_verify.py`, `tests/cli/test_kyvern_report.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/cli/test_kyvern_verify.py`:

```python
def _append_signed_by_new_key(workspace, tmp_path):
    """Append one decision signed by a second key; return that key's public PEM path."""
    from services.decision.audit_chain import sign_decision

    new_key = ed25519.Ed25519PrivateKey.generate()
    new_pub = tmp_path / "new.pub"
    new_pub.write_bytes(new_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    last = workspace["chain"][-1]
    d = {k: v for k, v in last.items() if k not in ("signature", "payload_hash", "key_id")}
    d["track_id"] = "track_new_key"
    d["chain_index"] = last["chain_index"] + 1
    signed = sign_decision(d, prev_hash=last["payload_hash"], signing_key=new_key)
    with open(workspace["chain_path"], "a", encoding="utf-8") as f:
        f.write(json.dumps(signed) + "\n")
    return new_pub


def test_verify_accepts_several_pubkeys(temp_workspace, tmp_path):
    new_pub = _append_signed_by_new_key(temp_workspace, tmp_path)
    args = [str(temp_workspace["chain_path"]), "--policy", str(temp_workspace["policy_path"])]

    both = run_cli(*args, "--pubkey", str(temp_workspace["pub_path"]), "--pubkey", str(new_pub))
    assert both.returncode == 0, both.stdout
    assert "Chain integrity: VALID (4 decisions" in both.stdout

    old_only = run_cli(*args, "--pubkey", str(temp_workspace["pub_path"]))
    assert old_only.returncode == 1
    assert "signed by unknown key" in old_only.stdout


def test_json_output_lists_key_ids_and_reason(temp_workspace, tmp_path):
    from services.decision.audit_chain import key_id

    new_pub = _append_signed_by_new_key(temp_workspace, tmp_path)
    res = run_cli(
        str(temp_workspace["chain_path"]),
        "--policy", str(temp_workspace["policy_path"]),
        "--pubkey", str(temp_workspace["pub_path"]),
        "--json",
    )
    data = json.loads(res.stdout)
    old_id = key_id(temp_workspace["private_key"].public_key())
    new_id = key_id(serialization.load_pem_public_key(new_pub.read_bytes()))
    assert data["key_ids"] == sorted([old_id, new_id])
    assert data["reason"] == f"signed by unknown key {new_id}"


def test_live_pipeline_decisions_verify(tmp_path, isolated_home):
    """End to end: decisions produced by the live pipeline pass kyvern-verify."""
    from services.decision.roe import load_roe
    from services.decision.threat_graph import decide_full

    clear_policy_cache()
    policy = Path(__file__).parent.parent.parent / "config" / "policies" / "default.yaml"
    chain = tmp_path / "chain.jsonl"
    rules = load_roe(policy)
    for i in range(3):
        decide_full(
            {
                "track_id": f"live-{i}", "latitude": 40.0, "longitude": 33.0,
                "altitude": 100.0, "confidence": 0.9, "hits": 10,
                "vx": 5.0, "vy": 0.0, "vz": 0.0, "x": 0.0, "y": 0.0, "z": 100.0,
                "sources": ["camera"],
            },
            rules, policy_path=str(policy), chain_path=chain,
        )
    pub = isolated_home / ".kyvern" / "keys" / "signing.pub"
    res = run_cli(str(chain), "--policy", str(policy), "--pubkey", str(pub))
    assert res.returncode == 0, res.stdout
    assert "Chain integrity: VALID (3 decisions" in res.stdout
```

Append to `tests/cli/test_kyvern_report.py`:

```python
def test_report_accepts_several_pubkeys(workspace):
    from services.decision.audit_chain import sign_decision

    new_key = ed25519.Ed25519PrivateKey.generate()
    new_pub = workspace["tmp"] / "new.pub"
    new_pub.write_bytes(new_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    last = workspace["chain"][-1]
    d = {k: v for k, v in last.items() if k not in ("signature", "payload_hash", "key_id")}
    d["chain_index"] = last["chain_index"] + 1
    signed = sign_decision(d, prev_hash=last["payload_hash"], signing_key=new_key)
    with open(workspace["chain_path"], "a", encoding="utf-8") as f:
        f.write(json.dumps(signed) + "\n")

    out = workspace["tmp"] / "report.pdf"
    res = _run(
        str(workspace["chain_path"]),
        "--policy", str(workspace["policy_path"]),
        "--pubkey", str(workspace["pub_path"]),
        "--pubkey", str(new_pub),
        "--output", str(out),
    )
    assert res.returncode == 0, res.stderr
    assert "[chain: VALID]" in res.stdout
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python -m pytest -q -p no:cacheprovider tests/cli`
Expected: 3 failures — the CLIs keep only the last `--pubkey` (so the "both keys" runs fail) and the JSON output has no `key_ids`. `test_live_pipeline_decisions_verify` already passes (Task 5 did the recording); it is the end-to-end guard.

- [ ] **Step 3: Implement in `cli/kyvern_verify.py`**

(a) Import line becomes:

```python
from services.decision.audit_chain import (
    Keyring,
    describe_chain_failure,
    verify_chain,
    verify_decision_against_policy,
)
```

(b) The `--pubkey` argument becomes:

```python
    parser.add_argument(
        "--pubkey", required=True, action="append",
        help="path to a PEM-encoded Ed25519 public key; repeat for chains signed by several keys",
    )
```

(c) Replace `public_key = load_pubkey(args.pubkey)` through the `errors.append(f"Chain integrity broken at index {broken_idx}")` block with:

```python
    public_key = Keyring([load_pubkey(p) for p in args.pubkey])

    is_valid_chain, broken_idx = verify_chain(decisions, public_key)
    errors = []
    failure_reason = None

    if not is_valid_chain:
        failure_reason = describe_chain_failure(decisions, broken_idx, public_key)
        errors.append(f"Chain integrity broken at index {broken_idx}: {failure_reason}")

    key_ids = sorted({d["key_id"] for d in decisions if d.get("key_id")})
```

(d) In the `--json` output dict add, after `"policy_version_id": policy_hash,`:

```python
            "key_ids": key_ids,
            "reason": failure_reason,
```

(e) The human INVALID line becomes:

```python
        print(f"{RED_CROSS} Chain integrity: INVALID (Broken at index {broken_idx}: {failure_reason})")
```

- [ ] **Step 4: Implement in `cli/kyvern_report.py`**

(a) Import line becomes `from services.decision.audit_chain import Keyring, verify_chain`.

(b) Delete `compute_pubkey_fingerprint()` (no other callers).

(c) The `--pubkey` argument becomes:

```python
    parser.add_argument("--pubkey", required=True, action="append",
                        help="path to an Ed25519 public key PEM; repeat for chains signed by several keys")
```

(d) Replace `public_key = _load_pubkey(args.pubkey)` with `public_key = Keyring([_load_pubkey(p) for p in args.pubkey])`, and `pubkey_fp = compute_pubkey_fingerprint(args.pubkey)` with `pubkey_fp = ", ".join(public_key.ids())`.

(e) In `generate_pdf`'s page 6 paragraph, replace the text `Public key fingerprint (SHA-256, first 16 hex chars): ` with `Signing key ID(s) (SHA-256 of the raw public key, first 16 hex chars): `.

(f) If ruff then reports `hashlib` as unused, remove that import; it is still used if `compute_report_fingerprint` uses it.

- [ ] **Step 5: Run the tests**

Run: `python -m pytest -q -p no:cacheprovider tests/cli`
Expected: all pass.

Run: `python -m pytest -q -p no:cacheprovider`
Expected: `247 passed, 3 skipped`.

- [ ] **Step 6: Lint and commit**

Run: `python -m ruff check .` → `All checks passed!`

```bash
git add cli/kyvern_verify.py cli/kyvern_report.py tests/cli/test_kyvern_verify.py tests/cli/test_kyvern_report.py
git commit -m "feat: kyvern-verify and kyvern-report accept several --pubkey and name failures"
```

---

### Task 7: `kyvern-mcp` uses a keyring and the shared chain default

**Files:**
- Modify: `kyvern/audit/store.py`, `kyvern/mcp/server.py`
- Test: `tests/mcp/test_server.py`, `tests/audit/test_store.py`

- [ ] **Step 1: Write the failing tests**

In `tests/mcp/test_server.py`, replace `test_parse_args_defaults` with:

```python
def test_parse_args_defaults(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    ns = parse_args([])
    assert Path(ns.chain_file) == tmp_path / ".kyvern" / "chain.jsonl"
    assert [Path(p) for p in ns.pubkey] == [tmp_path / ".kyvern" / "keys" / "signing.pub"]
    assert ns.verify_on_query is True
```

and append:

```python
def test_parse_args_accepts_several_pubkeys():
    ns = parse_args(["--pubkey", "a.pub", "--pubkey", "b.pub"])
    assert ns.pubkey == ["a.pub", "b.pub"]


def test_chain_default_matches_the_writer(tmp_path, monkeypatch):
    from services.decision.chain_writer import ChainWriter

    target = tmp_path / "shared.jsonl"
    monkeypatch.setenv("KYVERN_CHAIN_PATH", str(target))
    ChainWriter.open().append({"n": 1})
    assert Path(parse_args([]).chain_file) == target


def test_build_app_with_two_pubkeys(sample_chain_file, signing_keypair, tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    _, _, pub_path = signing_keypair
    other = tmp_path / "other.pub"
    other.write_bytes(ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    app = build_app(
        chain_file=sample_chain_file, pubkey=[pub_path, other],
        policy=None, verify_on_query=True,
    )
    assert app is not None
```

Append to `tests/audit/test_store.py`:

```python
def test_verify_chain_range_reports_the_reason(tampered_chain_file, signing_keypair):
    _, _, pub_path = signing_keypair
    store = AuditChainStore(tampered_chain_file, public_key_paths=[pub_path])
    store.load()
    result = store.verify_chain_range(None, None)
    assert result.integrity == "BROKEN"
    assert result.first_break == {"id": 1, "reason": "bad signature"}
```

(`signing_keypair` in `tests/audit/conftest.py` returns `(private_key, public_key, pub_path)`; `tampered_chain_file` flips `event[1].action` after signing, so entry 1 keeps its links and fails on the signature.)

- [ ] **Step 2: Run them to verify they fail**

Run: `python -m pytest -q -p no:cacheprovider tests/mcp/test_server.py tests/audit/test_store.py`
Expected: failures — `ns.pubkey` is a string, `--pubkey` keeps only the last value, `build_app` cannot take a list, `AuditChainStore` has no `public_key_paths`.

- [ ] **Step 3: Implement in `kyvern/audit/store.py`**

Replace the constructor and `_load_public_key` with:

```python
    def __init__(
        self,
        chain_file: Path,
        public_key_path: Path | None = None,
        verify_on_query: bool = True,
        reload_debounce_seconds: float = 1.0,
        public_key_paths: list[Path] | None = None,
    ) -> None:
        self._chain_file = Path(chain_file)
        self._verify_on_query = verify_on_query
        self._reload_debounce = reload_debounce_seconds
        self._events: list[dict] = []
        self._mtime: float | None = None
        self._last_check_monotonic: float = 0.0
        key_paths = [Path(p) for p in (public_key_paths or [])]
        if public_key_path is not None:
            key_paths.append(Path(public_key_path))
        self._keyring = None
        if key_paths:
            from services.decision.audit_chain import Keyring
            self._keyring = Keyring.from_pem_files(key_paths)
```

In `verify_event` and `verify_chain_range`, replace every `self._public_key` with `self._keyring`. In `verify_chain_range`, import `describe_chain_failure` next to `verify_chain`:

```python
        from services.decision.audit_chain import describe_chain_failure, verify_chain
```

and replace the `first_break={"id": broken_id, "reason": "signature_or_chain_link_invalid"},` line with:

```python
            first_break={
                "id": broken_id,
                "reason": describe_chain_failure(slice_events, broken_idx, self._keyring),
            },
```

Run `git grep -n "_public_key\b\|_load_public_key" -- kyvern tests` and update any remaining reference the same way.

- [ ] **Step 4: Implement in `kyvern/mcp/server.py`**

(a) The paths import becomes `from shared.paths import default_chain_path, kyvern_home`.

(b) In `parse_args`, the `--chain-file` default becomes `default=str(default_chain_path()),` and the `--pubkey` argument becomes:

```python
    parser.add_argument(
        "--pubkey",
        dest="pubkey",
        action="append",
        default=None,
        help="Ed25519 public key PEM; repeat for chains signed by several keys",
    )
```

and replace `return parser.parse_args(argv)` with:

```python
    ns = parser.parse_args(argv)
    if ns.pubkey is None:
        ns.pubkey = [str(kyvern_home() / "keys" / "signing.pub")]
    return ns
```

(c) In `build_app`, change the parameter to `pubkey: Path | str | list[Path | str] | None,` and replace from `pubkey_path = Path(pubkey) if pubkey else None` through the end of the `AuditChainStore(...)` call with:

```python
    raw_paths = pubkey if isinstance(pubkey, (list, tuple)) else [pubkey]
    pubkey_paths = [Path(p) for p in raw_paths if p]
    if verify_on_query:
        missing = [p for p in pubkey_paths if not p.exists()]
        if not pubkey_paths or missing:
            raise KyvernMCPError(
                f"public key not found at {missing[0] if missing else None} — "
                "pass --pubkey or use --no-verify-on-query"
            )

    store = AuditChainStore(
        chain_file=chain_file,
        public_key_paths=pubkey_paths if verify_on_query else None,
        verify_on_query=verify_on_query,
    )
```

- [ ] **Step 5: Run the tests**

Run: `python -m pytest -q -p no:cacheprovider tests/mcp tests/audit tests/test_runtime_event.py`
Expected: all pass.

Run: `python -m pytest -q -p no:cacheprovider`
Expected: `251 passed, 3 skipped`.

- [ ] **Step 6: Lint and commit**

Run: `python -m ruff check .` → `All checks passed!`

```bash
git add kyvern/audit/store.py kyvern/mcp/server.py tests/mcp/test_server.py tests/audit/test_store.py
git commit -m "feat: kyvern-mcp verifies with a keyring and shares the writer's chain default"
```

---

### Task 8: Documentation

**Files:**
- Modify: `docs/threat-model.md`, `docs/architecture.md`, `README.md`, `CHANGELOG.md`

- [ ] **Step 1: `docs/architecture.md`**

Replace step 5 of the data flow (the paragraph starting `5. **Audit chain**`) with:

```markdown
5. **Audit chain** — The finalized `Decision` (including raw LLM
   response, guardrail trace, rule reference, and full reasoning) is
   signed and appended to the JSONL audit chain by `ChainWriter`
   (`services/decision/chain_writer.py`): under an inter-process file
   lock it reads the last entry, links and signs the new one, writes it
   and fsyncs. The chain file is `run_graph(chain_path=...)`, else
   `$KYVERN_CHAIN_PATH`, else `~/.kyvern/chain.jsonl` — the same file
   `kyvern-verify`, `kyvern-report` and `kyvern-mcp` read. If the
   decision cannot be recorded, `run_graph()` raises `AuditWriteError`
   and returns nothing.
```

Replace the `**Current status:**` paragraph in §4 with:

```markdown
**Current status:** Every entry carries `signature`, `prev_hash`,
`payload_hash`, `chain_index` and `key_id` (the first 16 hex chars of
SHA-256 over the raw public key, covered by the signature). Decisions
from `run_graph()` and RuntimeEvents from `append_runtime_event()` are
both appended through `ChainWriter`, so they share one chain and one
`chain_index` sequence. Several processes on one host can append
safely; several hosts writing one chain is not supported.
```

and change the code example below it to:

```python
from services.decision.audit_chain import Keyring, describe_chain_failure, verify_chain

keys = Keyring.from_pem_files(["signing.pub", "signing-<old key id>.pub"])
is_valid, broken_idx = verify_chain(decisions, keys)
if not is_valid:
    print(f"Chain broken at index {broken_idx}: "
          f"{describe_chain_failure(decisions, broken_idx, keys)}")
```

- [ ] **Step 2: `docs/threat-model.md`**

Change the `> Last updated:` line to `> Last updated: 2026-10-07 · Status: pre-1.0`.

Insert this section before `## Threats Kyvern Explicitly Does NOT Defend Against`:

```markdown
## Recording Guarantees

- **No unrecorded decision.** `run_graph()` returns a decision only after it
  has been appended to the chain and fsynced. If that fails — disk error,
  lock timeout, corrupt chain tail, missing signing key for an existing
  chain — it raises `AuditWriteError` and returns nothing; the caller decides
  how to fail safe.
- **One chain per host.** Decisions and RuntimeEvents from several processes
  on the same host append through one inter-process lock, so the chain does
  not fork. Several hosts writing one chain is not supported.
- **Every entry names its key.** `key_id` is part of the signed payload.
  A verifier given the wrong key reports "signed by unknown key <id>" instead
  of a generic failure, and the signing key is never silently re-created
  next to a non-empty chain.
- **Still open: the keyholder.** Whoever holds the signing key can rewrite
  the chain from any point and re-sign it forward; nothing inside the chain
  proves that did not happen. Periodic external anchoring of the chain head
  (RFC 3161 timestamping, v0.3.0 part B) is the planned defense.

### Rotating the signing key

1. Stop every process that appends to the chain.
2. Note the current key id:
   `python -c "from pathlib import Path; from cryptography.hazmat.primitives import serialization; from services.decision.audit_chain import key_id; print(key_id(serialization.load_pem_public_key((Path.home()/'.kyvern'/'keys'/'signing.pub').read_bytes())))"`
3. Copy `~/.kyvern/keys/signing.pub` to `~/.kyvern/keys/signing-<old key id>.pub`
   and move `signing.key` to offline storage.
4. Create the new pair:

   ```python
   from pathlib import Path
   from cryptography.hazmat.primitives import serialization
   from cryptography.hazmat.primitives.asymmetric import ed25519

   keys = Path.home() / ".kyvern" / "keys"
   key = ed25519.Ed25519PrivateKey.generate()
   (keys / "signing.key").write_bytes(key.private_bytes(
       serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
       serialization.NoEncryption()))
   (keys / "signing.pub").write_bytes(key.public_key().public_bytes(
       serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
   ```

5. Restart the writers, then verify with both keys:
   `kyvern-verify chain.jsonl --policy <policy> --pubkey ~/.kyvern/keys/signing-<old key id>.pub --pubkey ~/.kyvern/keys/signing.pub`
```

- [ ] **Step 3: `README.md`**

After the `kyvern-verify` example block in "Verifying decisions", add:

```markdown
Repeat `--pubkey` to verify a chain signed by more than one key (for example
after a key rotation); every entry records which key signed it.
```

In "Recording events from your existing stack", after the opening paragraph and before the code block, add:

```markdown
Decisions from `run_graph()` are appended to the chain automatically
(`~/.kyvern/chain.jsonl` by default; override with `chain_path=` or
`KYVERN_CHAIN_PATH`). If a decision cannot be recorded, `run_graph()` raises
`AuditWriteError` instead of returning it.
```

- [ ] **Step 4: `CHANGELOG.md` `[Unreleased]`**

Append to `### Added`:

```markdown
- `ChainWriter`: one inter-process-locked, fsynced append path for Decisions
  and RuntimeEvents; refuses to append after a corrupt chain tail
- Signed `key_id` on every chain entry; `Keyring` and repeatable `--pubkey`
  in `kyvern-verify`, `kyvern-report` and `kyvern-mcp` for chains signed by
  several keys; verification failures name their reason
- `run_graph(chain_path=...)` / `decide_full(chain_path=...)` and
  `KYVERN_CHAIN_PATH`
```

Add at the top of `### Changed` (above the rename entry):

```markdown
- **Decisions are now recorded in the JSONL audit chain**
  (`~/.kyvern/chain.jsonl` by default), the same file the verifiers read.
  Breaking:
  - `run_graph()` / `decide_full()` raise `AuditWriteError` when a decision
    cannot be recorded, instead of returning it
  - Postgres recording, `KYVERN_DB_DSN` and the `asyncpg` dependency are removed
  - the signing key is no longer auto-created next to a non-empty chain
  - chains containing `key_id` need this version to verify
```

- [ ] **Step 5: Check and commit**

Run: `git grep -n -i -e asyncpg -e DB_DSN -- . ':!docs/superpowers' ':!CHANGELOG.md'`
Expected: no output.

Run: `python -m mkdocs build --strict -q -d <scratchpad>\site-check` (only if mkdocs is installed), then delete that directory.
Expected: exit 0.

```bash
git add docs/threat-model.md docs/architecture.md README.md CHANGELOG.md
git commit -m "docs: recording guarantees, key rotation, and the single JSONL chain"
```

---

### Task 9: Acceptance, push and PR

- [ ] **Step 1: Full suite and lint**

Run: `python -m pytest -q -p no:cacheprovider` → `251 passed, 3 skipped`
Run: `python -m ruff check .` → `All checks passed!`

- [ ] **Step 2: The real home directory is unchanged**

Re-run the command from Task 1 Step 1 and compare: same two files, same hashes, no `chain.jsonl` in the real `~/.kyvern`.

- [ ] **Step 3: Install the new dependency locally if needed**

`filelock` is already installed on the dev machine (3.25.2). CI installs it from `requirements.txt`.

- [ ] **Step 4: Push and open the PR**

```bash
git push -u origin feat/audit-path
gh pr create --repo altunbulakemre75/kyvern --base main --head feat/audit-path --title "v0.3.0 part A: one verifiable audit chain" --body-file <scratchpad>/pr_audit_body.md
```

`<scratchpad>/pr_audit_body.md` (replace `<N>` with the passed count from Step 1):

```markdown
## Summary
- **Decisions from the live pipeline now reach the verifiable chain.** `run_graph()` appends every decision to the JSONL chain (`~/.kyvern/chain.jsonl` by default, `chain_path=` / `KYVERN_CHAIN_PATH` to override) — the file `kyvern-verify`, `kyvern-report` and `kyvern-mcp` read. Postgres recording is removed.
- **Fail-closed.** If a decision cannot be recorded, `run_graph()` raises `AuditWriteError` instead of returning it.
- **Safe concurrent appends.** `ChainWriter` holds an inter-process file lock, checks the chain tail, signs, writes and fsyncs. Decisions and RuntimeEvents share it.
- **Key identity.** Every entry carries a signed `key_id`; `kyvern-verify`, `kyvern-report` and `kyvern-mcp` accept several `--pubkey` and name the failure reason ("signed by unknown key …", "broken prev_hash link", …). The signing key is never silently re-created next to a non-empty chain.
- Tests no longer touch the developer's real `~/.kyvern`.
- Spec: `docs/superpowers/specs/2026-10-07-audit-path-design.md`; plan: `docs/superpowers/plans/2026-10-07-audit-path.md`. Part B (RFC 3161 anchoring) follows separately.

## Breaking changes
- `run_graph()` / `decide_full()` may raise `AuditWriteError`
- `KYVERN_DB_DSN` and `asyncpg` removed
- New dependency: `filelock`

## Test plan
- [x] <N> passed, 3 skipped; `ruff check .` clean
- [x] End to end: decisions from `decide_full()` pass `kyvern-verify`
- [x] 4 processes × 25 appends → one unbroken chain (0–99)
- [x] Unrecordable decision → `AuditWriteError`
- [x] Real `~/.kyvern` unchanged after the suite
- [ ] CI green on this PR (Linux, Python 3.10–3.12, LangGraph installed)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
```

- [ ] **Step 5: Hand over**

Report the PR link and CI result; the user merges.
