# v0.3.0 Part B — RFC 3161 Anchoring: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `kyvern-anchor` obtains an RFC 3161 timestamp (IdenTrust by default) over the current chain head and stores the receipt in `<stem>.anchors.jsonl`; `kyvern-verify` checks every receipt against the chain, so a chain rewritten after an anchor fails verification even if it was re-signed with the right key.

**Architecture:** `services/decision/anchors.py` holds the generic part (statement format, `Anchor` protocol, receipts file, `anchor_head`, `check_anchors`). `services/decision/rfc3161_anchor.py` is the first `Anchor`: it builds the request with `rfc3161-client`, POSTs it with `urllib.request`, and verifies responses against `certifi` roots at the token's `genTime`. Two CLIs use them: the new `cli/kyvern_anchor.py` and the existing `cli/kyvern_verify.py`.

**Tech Stack:** Python 3.10–3.13, `rfc3161-client` 1.0.9 (installed locally), `certifi`, `cryptography`, `filelock`, pytest, ruff.

**Spec:** `docs/superpowers/specs/2026-10-07-anchoring-design.md`
**Branch:** `feat/anchoring` (from `main` at `0d0d96a`; spec commits `f038c5d`, `e0030ce`).

**Test count:** 251 passed, 3 skipped before this work. Each task states the expected total after it.

**Run tests with:** `python -m pytest -q -p no:cacheprovider` (add a path to narrow). **Lint with:** `python -m ruff check .`

**`<scratchpad>`** means `C:\Users\altun\AppData\Local\Temp\claude\C--Users-altun-Desktop-Yeni-klas-r-kernel\e0dd28f8-16c4-4728-a9f9-fe35f6b37298\scratchpad`.

---

## File map

| File | Responsibility | Change |
|---|---|---|
| `requirements.txt` | Dependencies | Add `rfc3161-client>=1.0.9`, `certifi` |
| `services/decision/chain_writer.py` | Chain appender | Rename `_last_entry` → `last_entry` (now used by anchors) |
| `services/decision/anchors.py` | **New.** Generic anchoring | statement, `Anchor`, `AnchorError`, `AnchorResult`, receipts file, `anchor_head`, `AnchorReport`, `check_anchors` |
| `services/decision/rfc3161_anchor.py` | **New.** RFC 3161 anchor | `DEFAULT_TSA_URL`, `load_roots`, `RFC3161Anchor` |
| `cli/kyvern_anchor.py` | **New.** CLI | `kyvern-anchor` |
| `cli/kyvern_verify.py` | CLI | `--anchors`, `--tsa-root`, anchors output and exit code |
| `pyproject.toml` | Packaging | `kyvern-anchor` script |
| `tests/decision/fake_anchor.py` | **New.** Test double | `FakeAnchor` |
| `tests/decision/test_anchors.py` | **New.** | Generic anchoring tests |
| `tests/decision/test_rfc3161_anchor.py` | **New.** | RFC 3161 tests (offline, fixture) + live test (env-gated) |
| `tests/fixtures/rfc3161/` | **New.** Recorded fixture | `record_fixture.py`, `policy.yaml`, `signing.key`, `signing.pub`, `chain.jsonl`, `chain.anchors.jsonl` |
| `tests/cli/test_kyvern_anchor.py` | **New.** | CLI tests |
| `tests/cli/test_kyvern_verify.py` | | Anchors tests |
| `docs/threat-model.md`, `docs/architecture.md`, `README.md`, `CHANGELOG.md` | Docs | Anchoring |

---

### Task 1: Generic anchoring core

**Files:**
- Modify: `requirements.txt`, `services/decision/chain_writer.py`
- Create: `services/decision/anchors.py`, `tests/decision/fake_anchor.py`, `tests/decision/test_anchors.py`

- [ ] **Step 1: Dependencies**

In `requirements.txt`, after the `filelock>=3.12.0 …` line add:

```
rfc3161-client>=1.0.9  # RFC 3161 timestamps for anchoring; <1.0.3 had CVE-2025-52556
certifi  # trusted roots for verifying TSA timestamps
```

Run: `python -c "import rfc3161_client, certifi; print('ok')"` → `ok` (rfc3161-client 1.0.9 is already installed on the dev machine).

- [ ] **Step 2: Make the chain tail reader public**

In `services/decision/chain_writer.py` rename `def _last_entry(path: Path)` to `def last_entry(path: Path)` and its one call in `_append_locked` (`last = _last_entry(self._chain_path)`) to `last = last_entry(self._chain_path)`. Add this docstring as its first line:

```python
    """The last chain entry, None for an empty or missing chain; AuditWriteError if the tail is corrupt."""
```

Run: `python -m pytest -q -p no:cacheprovider tests/decision/test_chain_writer.py` → `9 passed`.

- [ ] **Step 3: Write the test double**

Create `tests/decision/fake_anchor.py`:

```python
"""A deterministic in-memory Anchor for tests that must not touch the network."""
from __future__ import annotations

import hashlib
from typing import Any

from services.decision.anchors import AnchorError, AnchorResult


class FakeAnchor:
    name = "fake"

    def __init__(self, *args: Any, fail: bool = False, valid: bool = True, **kwargs: Any) -> None:
        self.statements: list[bytes] = []
        self.fail = fail
        self.valid = valid

    def request(self, statement: bytes) -> dict[str, Any]:
        if self.fail:
            raise AnchorError("fake TSA is down")
        self.statements.append(statement)
        return {
            "anchored_at": "2026-10-07T12:00:00Z",
            "tsa_url": "fake://tsa",
            "proof": hashlib.sha256(statement).hexdigest(),
        }

    def verify(self, statement: bytes, receipt: dict[str, Any]) -> AnchorResult:
        if not self.valid:
            return AnchorResult(ok=False, reason="fake says no")
        if receipt.get("proof") != hashlib.sha256(statement).hexdigest():
            return AnchorResult(ok=False, reason="proof does not cover the statement")
        return AnchorResult(ok=True, anchored_at=receipt["anchored_at"])
```

- [ ] **Step 4: Write the failing tests**

Create `tests/decision/test_anchors.py`:

```python
"""Generic anchoring: statement, receipts file, anchor_head, check_anchors."""
from __future__ import annotations

import json
import os

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from services.decision import anchors
from services.decision.anchors import (
    AnchorError,
    anchor_head,
    anchor_statement,
    anchors_path_for,
    append_receipt,
    check_anchors,
    read_receipts,
)
from services.decision.chain_writer import ChainWriter
from tests.decision.fake_anchor import FakeAnchor


@pytest.fixture
def chain(tmp_path):
    path = tmp_path / "chain.jsonl"
    writer = ChainWriter(path, ed25519.Ed25519PrivateKey.generate())
    writer.append({"n": 0})
    writer.append({"n": 1})
    return path, writer


def _entries(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_statement_is_deterministic_and_names_the_entry():
    s = anchor_statement(4, "ab" * 32)
    assert s == anchor_statement(4, "ab" * 32)
    assert s == b'{"chain_index":4,"kyvern_anchor":1,"payload_hash":"' + b"ab" * 32 + b'"}'
    assert s != anchor_statement(5, "ab" * 32)
    assert s != anchor_statement(4, "cd" * 32)


def test_anchors_path_sits_next_to_the_chain(tmp_path):
    assert anchors_path_for(tmp_path / "chain.jsonl") == tmp_path / "chain.anchors.jsonl"


def test_receipts_round_trip_and_are_fsynced(tmp_path, monkeypatch):
    calls = []
    real_fsync = os.fsync
    monkeypatch.setattr(anchors.os, "fsync", lambda fd: (calls.append(fd), real_fsync(fd)))
    path = tmp_path / "chain.anchors.jsonl"
    append_receipt(path, {"anchor": "fake", "chain_index": 0})
    append_receipt(path, {"anchor": "fake", "chain_index": 1})
    assert read_receipts(path) == [
        {"anchor": "fake", "chain_index": 0},
        {"anchor": "fake", "chain_index": 1},
    ]
    assert len(calls) == 2
    assert read_receipts(tmp_path / "missing.jsonl") == []


def test_anchor_head_anchors_the_last_entry(chain):
    path, _ = chain
    fake = FakeAnchor()
    receipt = anchor_head(path, fake)
    head = _entries(path)[-1]
    assert receipt["anchor"] == "fake"
    assert (receipt["chain_index"], receipt["payload_hash"]) == (1, head["payload_hash"])
    assert fake.statements == [anchor_statement(1, head["payload_hash"])]
    assert read_receipts(anchors_path_for(path)) == [receipt]


def test_anchor_head_skips_an_already_anchored_head(chain):
    path, _ = chain
    fake = FakeAnchor()
    anchor_head(path, fake)
    assert anchor_head(path, fake) is None
    assert len(fake.statements) == 1


def test_anchor_head_anchors_again_after_new_entries(chain):
    path, writer = chain
    fake = FakeAnchor()
    anchor_head(path, fake)
    writer.append({"n": 2})
    assert anchor_head(path, fake)["chain_index"] == 2
    assert len(read_receipts(anchors_path_for(path))) == 2


def test_anchor_head_on_an_empty_chain_returns_none(tmp_path):
    fake = FakeAnchor()
    assert anchor_head(tmp_path / "chain.jsonl", fake) is None
    assert fake.statements == []


def test_anchor_failure_writes_nothing(chain):
    path, _ = chain
    with pytest.raises(AnchorError):
        anchor_head(path, FakeAnchor(fail=True))
    assert not anchors_path_for(path).exists()


def test_check_anchors_counts_valid_receipts_and_the_unanchored_tail(chain):
    path, writer = chain
    fake = FakeAnchor()
    anchor_head(path, fake)
    writer.append({"n": 2})
    writer.append({"n": 3})
    report = check_anchors(_entries(path), read_receipts(anchors_path_for(path)), {"fake": fake})
    assert report.valid == 1
    assert report.failures == []
    assert (report.latest_index, report.latest_time) == (1, "2026-10-07T12:00:00Z")
    assert report.unanchored_tail == 2


def test_check_anchors_detects_a_rewritten_entry(chain):
    path, _ = chain
    fake = FakeAnchor()
    anchor_head(path, fake)
    entries = _entries(path)
    entries[1]["payload_hash"] = "ff" * 32  # rewritten after it was anchored
    report = check_anchors(entries, read_receipts(anchors_path_for(path)), {"fake": fake})
    assert report.valid == 0
    assert "does not match the anchored hash" in report.failures[0]


def test_check_anchors_reports_a_missing_entry(chain):
    path, _ = chain
    fake = FakeAnchor()
    anchor_head(path, fake)
    report = check_anchors(_entries(path)[:1], read_receipts(anchors_path_for(path)), {"fake": fake})
    assert report.failures == ["receipt 0: chain entry 1 is missing"]


def test_check_anchors_reports_an_unknown_anchor_type(chain):
    path, _ = chain
    anchor_head(path, FakeAnchor())
    report = check_anchors(_entries(path), read_receipts(anchors_path_for(path)), {})
    assert report.failures == ["receipt 0: unknown anchor type 'fake'"]


def test_check_anchors_reports_a_receipt_that_does_not_verify(chain):
    path, _ = chain
    anchor_head(path, FakeAnchor())
    report = check_anchors(
        _entries(path), read_receipts(anchors_path_for(path)), {"fake": FakeAnchor(valid=False)}
    )
    assert report.failures == ["receipt 0: fake says no"]
    assert report.latest_index is None
    assert report.unanchored_tail == 2
```

- [ ] **Step 5: Run them to verify they fail**

Run: `python -m pytest -q -p no:cacheprovider tests/decision/test_anchors.py`
Expected: collection ERROR — `No module named 'services.decision.anchors'`.

- [ ] **Step 6: Create `services/decision/anchors.py`**

```python
"""Anchors — external evidence that a chain entry existed at a given time.

An Anchor turns a short statement naming one chain entry into a receipt from an
independent party (an RFC 3161 Time Stamping Authority today). Receipts live
next to the chain in <stem>.anchors.jsonl; check_anchors() compares them with
the chain. If an anchored entry is later rewritten, its payload_hash no longer
matches the receipt, whoever holds the signing key.
"""
from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from filelock import FileLock

from services.decision.chain_writer import last_entry

ANCHOR_STATEMENT_VERSION = 1


class AnchorError(RuntimeError):
    """An anchor could not be obtained or did not verify."""


@dataclass(frozen=True)
class AnchorResult:
    ok: bool
    anchored_at: str | None = None  # ISO-8601 UTC time asserted by the anchor itself
    reason: str | None = None


class Anchor(Protocol):
    name: str

    def request(self, statement: bytes) -> dict[str, Any]:
        """Anchor `statement`; return receipt fields (including "anchored_at"). Raises AnchorError."""
        ...

    def verify(self, statement: bytes, receipt: dict[str, Any]) -> AnchorResult:
        """Check that `receipt` proves `statement`. Never raises."""
        ...


def anchor_statement(chain_index: int, payload_hash: str) -> bytes:
    """The bytes an anchor certifies for one chain entry."""
    return json.dumps(
        {
            "chain_index": chain_index,
            "kyvern_anchor": ANCHOR_STATEMENT_VERSION,
            "payload_hash": payload_hash,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def anchors_path_for(chain_path: Path) -> Path:
    """chain.jsonl -> chain.anchors.jsonl, in the same directory."""
    chain_path = Path(chain_path)
    return chain_path.with_name(chain_path.stem + ".anchors.jsonl")


def read_receipts(anchors_path: Path) -> list[dict[str, Any]]:
    path = Path(anchors_path)
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def append_receipt(anchors_path: Path, receipt: dict[str, Any]) -> None:
    path = Path(anchors_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with FileLock(str(path) + ".lock", timeout=10):
        with open(path, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(receipt, separators=(",", ":")) + "\n")
            f.flush()
            os.fsync(f.fileno())


def anchor_head(chain_path: Path, anchor: Anchor) -> dict[str, Any] | None:
    """Anchor the last chain entry. Returns the stored receipt, or None if the chain is
    empty or its head is already anchored. Raises AnchorError / AuditWriteError."""
    chain_path = Path(chain_path)
    head = last_entry(chain_path)
    if head is None:
        return None
    anchors_path = anchors_path_for(chain_path)
    receipts = read_receipts(anchors_path)
    if receipts and (
        receipts[-1].get("chain_index") == head["chain_index"]
        and receipts[-1].get("payload_hash") == head["payload_hash"]
    ):
        return None
    statement = anchor_statement(head["chain_index"], head["payload_hash"])
    receipt = {
        "anchor": anchor.name,
        "chain_index": head["chain_index"],
        "payload_hash": head["payload_hash"],
        **anchor.request(statement),
    }
    append_receipt(anchors_path, receipt)
    return receipt


@dataclass(frozen=True)
class AnchorReport:
    valid: int
    failures: list[str]
    latest_index: int | None
    latest_time: str | None
    unanchored_tail: int


def check_anchors(
    entries: list[dict[str, Any]],
    receipts: list[dict[str, Any]],
    anchors: Mapping[str, Anchor],
) -> AnchorReport:
    """Check every receipt against the chain entries and its anchor."""
    by_index = {e.get("chain_index"): e for e in entries}
    valid = 0
    failures: list[str] = []
    latest: tuple[int, str | None] | None = None

    for i, receipt in enumerate(receipts):
        n = receipt.get("chain_index")
        anchor = anchors.get(receipt.get("anchor"))
        if anchor is None:
            failures.append(f"receipt {i}: unknown anchor type '{receipt.get('anchor')}'")
            continue
        entry = by_index.get(n)
        if entry is None:
            failures.append(f"receipt {i}: chain entry {n} is missing")
            continue
        result = anchor.verify(anchor_statement(n, receipt.get("payload_hash")), receipt)
        if entry.get("payload_hash") != receipt.get("payload_hash"):
            when = result.anchored_at if result.ok else "it was anchored"
            failures.append(
                f"receipt {i}: chain entry {n} does not match the anchored hash "
                f"(rewritten after {when}?)"
            )
            continue
        if not result.ok:
            failures.append(f"receipt {i}: {result.reason}")
            continue
        valid += 1
        if latest is None or n > latest[0]:
            latest = (n, result.anchored_at)

    latest_index = latest[0] if latest else None
    unanchored_tail = sum(
        1 for e in entries
        if latest_index is None or e.get("chain_index", -1) > latest_index
    )
    return AnchorReport(
        valid=valid,
        failures=failures,
        latest_index=latest_index,
        latest_time=latest[1] if latest else None,
        unanchored_tail=unanchored_tail,
    )
```

- [ ] **Step 7: Run the tests**

Run: `python -m pytest -q -p no:cacheprovider tests/decision/test_anchors.py` → `13 passed`.
Run: `python -m pytest -q -p no:cacheprovider` → `264 passed, 3 skipped`.

- [ ] **Step 8: Lint and commit**

Run: `python -m ruff check .` → `All checks passed!`

```bash
git add requirements.txt services/decision/chain_writer.py services/decision/anchors.py tests/decision/fake_anchor.py tests/decision/test_anchors.py
git commit -m "feat: generic anchoring core — statement, receipts file, anchor_head, check_anchors"
```

---

### Task 2: RFC 3161 anchor and the recorded fixture

**Files:**
- Create: `services/decision/rfc3161_anchor.py`
- Create: `tests/fixtures/rfc3161/record_fixture.py` and the files it writes
- Create: `tests/decision/test_rfc3161_anchor.py`

- [ ] **Step 1: Create `services/decision/rfc3161_anchor.py`**

(The fixture recorder in Step 2 needs it, so it comes first; its tests follow in Step 3.)

```python
"""RFC 3161 anchor — timestamps from an external Time Stamping Authority (TSA).

The TSA signs the SHA-256 of the anchor statement together with its own time.
Requests and responses use rfc3161-client; the HTTP POST uses the standard
library. Responses are verified against trusted roots at the token's genTime,
so receipts remain verifiable after the TSA certificate expires.
"""
from __future__ import annotations

import base64
import urllib.error
import urllib.request
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from rfc3161_client import (
    TimestampRequestBuilder,
    VerificationError,
    VerifierBuilder,
    decode_timestamp_response,
)

from services.decision.anchors import AnchorError, AnchorResult

# IdenTrust's TSA chains to a root in the certifi bundle. DigiCert, Sectigo,
# GlobalSign and Entrust return non-strict DER that rfc3161-client rejects
# (see docs/superpowers/specs/2026-10-07-anchoring-design.md §2.1).
DEFAULT_TSA_URL = "http://timestamp.identrust.com"


def load_roots(pem_paths: Iterable[str | Path] | None = None) -> list[x509.Certificate]:
    """Trusted TSA roots from the given PEM files, else from the certifi bundle."""
    paths = list(pem_paths) if pem_paths else [certifi.where()]
    roots: dict[bytes, x509.Certificate] = {}
    for path in paths:
        for cert in x509.load_pem_x509_certificates(Path(path).read_bytes()):
            roots[cert.fingerprint(hashes.SHA256())] = cert
    return list(roots.values())


def _iso_utc(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class RFC3161Anchor:
    name = "rfc3161"

    def __init__(
        self,
        tsa_url: str = DEFAULT_TSA_URL,
        roots: list[x509.Certificate] | None = None,
        timeout_s: float = 30.0,
    ) -> None:
        self.tsa_url = tsa_url
        self._roots = roots if roots is not None else load_roots()
        self._timeout_s = timeout_s

    def request(self, statement: bytes) -> dict[str, Any]:
        tsq = (
            TimestampRequestBuilder()
            .data(statement)
            .nonce(nonce=True)
            .cert_request(cert_request=True)
            .build()
        )
        http_request = urllib.request.Request(
            self.tsa_url,
            data=tsq.as_bytes(),
            headers={"Content-Type": "application/timestamp-query"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(http_request, timeout=self._timeout_s) as response:
                body = response.read()
        except OSError as exc:  # URLError, HTTPError, timeouts
            raise AnchorError(f"could not reach {self.tsa_url}: {exc}") from exc

        receipt = {"tsa_url": self.tsa_url, "token": base64.b64encode(body).decode("ascii")}
        result = self.verify(statement, receipt, nonce=tsq.nonce)
        if not result.ok:
            raise AnchorError(f"{self.tsa_url} returned a timestamp that does not verify: {result.reason}")
        return {"anchored_at": result.anchored_at, **receipt}

    def verify(
        self, statement: bytes, receipt: dict[str, Any], nonce: int | None = None
    ) -> AnchorResult:
        try:
            response = decode_timestamp_response(base64.b64decode(receipt["token"]))
            verifier = VerifierBuilder(roots=list(self._roots), nonce=nonce).build()
            verifier.verify_message(response, statement)
        except (VerificationError, ValueError, KeyError, TypeError) as exc:
            return AnchorResult(ok=False, reason=f"timestamp does not verify: {exc}")
        return AnchorResult(ok=True, anchored_at=_iso_utc(response.tst_info.gen_time))
```

- [ ] **Step 2: Record the fixture (one network request to IdenTrust)**

Create `tests/fixtures/rfc3161/record_fixture.py`:

```python
"""Record the offline RFC 3161 fixture used by the anchoring tests.

Run once from the repo root:  python tests/fixtures/rfc3161/record_fixture.py
It creates a test-only key pair, a two-entry chain signed with it, and a real
IdenTrust timestamp for the chain head. Only the hash of the anchor statement
is sent to the TSA. Re-running overwrites the fixture.
"""
from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from services.decision.anchors import anchor_head, anchors_path_for
from services.decision.chain_writer import ChainWriter
from services.decision.policy_loader import load_policy
from services.decision.rfc3161_anchor import RFC3161Anchor

HERE = Path(__file__).parent
POLICY = """rules:
  - rule_id: "rule_1"
    description: "Fixture policy"
    when_threat_level: "low"
    requires_operator_approval: false
    action: "log"
    enabled: true
"""


def main() -> None:
    (HERE / "policy.yaml").write_text(POLICY, encoding="utf-8")
    policy = load_policy(str(HERE / "policy.yaml"))

    key = ed25519.Ed25519PrivateKey.generate()
    (HERE / "signing.key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    (HERE / "signing.pub").write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

    chain = HERE / "chain.jsonl"
    for path in (chain, anchors_path_for(chain)):
        path.unlink(missing_ok=True)
    writer = ChainWriter(chain, key)
    for i in range(2):
        writer.append({
            "track_id": f"fixture_{i}", "action": "log", "threat_level": "low",
            "confidence": 0.9, "reasoning": "fixture", "source": "rule_engine",
            "roe_reference": "rule_1", "requires_operator_approval": False,
            "timestamp_iso": f"2026-10-07T12:00:0{i}+00:00",
            "llm_raw_response": None, "llm_provider": None, "llm_model": None,
            "guardrails_triggered": [], "guardrail_reasoning": "",
            "policy_version_id": policy.version_id, "policy_path": "policy.yaml",
        })
    receipt = anchor_head(chain, RFC3161Anchor())
    print(f"recorded receipt for chain_index {receipt['chain_index']} at {receipt['anchored_at']}")


if __name__ == "__main__":
    main()
```

Run from the repo root (needs network): `python tests/fixtures/rfc3161/record_fixture.py`
Expected: `recorded receipt for chain_index 1 at 2026-10-07T…Z`, and the directory now holds `policy.yaml`, `signing.key`, `signing.pub`, `chain.jsonl`, `chain.anchors.jsonl` (plus `*.lock` files — delete them: `Remove-Item tests\fixtures\rfc3161\*.lock`).

The `.lock` files must not be committed. Add to `.gitignore`:

```
*.jsonl.lock
```

- [ ] **Step 3: Write the tests**

Create `tests/decision/test_rfc3161_anchor.py`:

```python
"""RFC 3161 anchor, tested offline against a recorded IdenTrust receipt."""
from __future__ import annotations

import base64
import io
import json
import os
from pathlib import Path

import pytest

from services.decision import rfc3161_anchor
from services.decision.anchors import AnchorError, anchor_statement
from services.decision.rfc3161_anchor import RFC3161Anchor

FIXTURE = Path(__file__).parent.parent / "fixtures" / "rfc3161"


@pytest.fixture(scope="module")
def recorded():
    receipt = json.loads((FIXTURE / "chain.anchors.jsonl").read_text(encoding="utf-8").splitlines()[0])
    statement = anchor_statement(receipt["chain_index"], receipt["payload_hash"])
    return statement, receipt


@pytest.fixture(scope="module")
def tsa():
    return RFC3161Anchor()  # default roots: certifi bundle


def test_recorded_receipt_verifies_with_default_roots(recorded, tsa):
    statement, receipt = recorded
    result = tsa.verify(statement, receipt)
    assert result.ok, result.reason
    assert result.anchored_at == receipt["anchored_at"]
    assert receipt["tsa_url"] == rfc3161_anchor.DEFAULT_TSA_URL


def test_receipt_does_not_cover_another_statement(recorded, tsa):
    statement, receipt = recorded
    result = tsa.verify(statement + b" ", receipt)
    assert not result.ok
    assert result.reason.startswith("timestamp does not verify")


def test_receipt_fails_without_trusted_roots(recorded):
    statement, receipt = recorded
    assert not RFC3161Anchor(roots=[]).verify(statement, receipt).ok


def test_corrupted_token_is_reported_not_raised(recorded, tsa):
    statement, receipt = recorded
    broken = dict(receipt, token=base64.b64encode(b"not a timestamp").decode())
    result = tsa.verify(statement, broken)
    assert not result.ok
    assert result.reason.startswith("timestamp does not verify")


class _FakeHTTPResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _serve(body: bytes):
    return lambda request, timeout: _FakeHTTPResponse(body)


def _anchor_ignoring_nonce(monkeypatch) -> RFC3161Anchor:
    """The recorded token carries the nonce of the original request, not of a new one,
    so request() is exercised with nonce checking switched off."""
    tsa = RFC3161Anchor()
    real_verify = tsa.verify
    monkeypatch.setattr(tsa, "verify", lambda s, r, nonce=None: real_verify(s, r))
    return tsa


def test_request_returns_receipt_fields(recorded, monkeypatch):
    statement, receipt = recorded
    monkeypatch.setattr(
        rfc3161_anchor.urllib.request, "urlopen", _serve(base64.b64decode(receipt["token"]))
    )
    fields = _anchor_ignoring_nonce(monkeypatch).request(statement)
    assert fields == {
        "anchored_at": receipt["anchored_at"],
        "tsa_url": rfc3161_anchor.DEFAULT_TSA_URL,
        "token": receipt["token"],
    }


def test_request_wraps_network_errors(monkeypatch):
    def down(request, timeout):
        raise OSError("connection refused")

    monkeypatch.setattr(rfc3161_anchor.urllib.request, "urlopen", down)
    with pytest.raises(AnchorError, match="could not reach"):
        RFC3161Anchor().request(b"statement")


def test_request_refuses_a_timestamp_for_another_statement(recorded, monkeypatch):
    statement, receipt = recorded
    monkeypatch.setattr(
        rfc3161_anchor.urllib.request, "urlopen", _serve(base64.b64decode(receipt["token"]))
    )
    with pytest.raises(AnchorError, match="does not verify"):
        _anchor_ignoring_nonce(monkeypatch).request(statement + b" ")


@pytest.mark.skipif(not os.environ.get("KYVERN_TSA_E2E"), reason="set KYVERN_TSA_E2E=1 to call IdenTrust")
def test_live_identrust_timestamp(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import ed25519

    from services.decision.anchors import anchor_head, anchors_path_for, check_anchors, read_receipts
    from services.decision.chain_writer import ChainWriter

    chain = tmp_path / "chain.jsonl"
    ChainWriter(chain, ed25519.Ed25519PrivateKey.generate()).append({"n": 1})
    receipt = anchor_head(chain, RFC3161Anchor())
    entries = [json.loads(line) for line in chain.read_text(encoding="utf-8").splitlines()]
    report = check_anchors(entries, read_receipts(anchors_path_for(chain)), {"rfc3161": RFC3161Anchor()})
    assert receipt is not None and report.valid == 1 and report.failures == []
```

The file has 7 offline tests and 1 live test.

- [ ] **Step 4: Run the tests**

Run: `python -m pytest -q -p no:cacheprovider tests/decision/test_rfc3161_anchor.py`
Expected: `7 passed, 1 skipped`.

Run: `python -m pytest -q -p no:cacheprovider` → `271 passed, 4 skipped`.

- [ ] **Step 5: Lint and commit**

Run: `python -m ruff check .` → `All checks passed!`

```bash
git add .gitignore services/decision/rfc3161_anchor.py tests/decision/test_rfc3161_anchor.py tests/fixtures/rfc3161
git commit -m "feat: RFC 3161 anchor (IdenTrust by default) with a recorded offline fixture"
```

---

### Task 3: `kyvern-anchor` command

**Files:**
- Create: `cli/kyvern_anchor.py`, `tests/cli/test_kyvern_anchor.py`
- Modify: `pyproject.toml` (`[project.scripts]`)

- [ ] **Step 1: Write the failing tests**

Create `tests/cli/test_kyvern_anchor.py`:

```python
"""kyvern-anchor, run in-process with the TSA replaced by FakeAnchor."""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from cli import kyvern_anchor
from services.decision.anchors import anchors_path_for, read_receipts
from services.decision.chain_writer import ChainWriter
from tests.decision.fake_anchor import FakeAnchor


@pytest.fixture
def fake_tsa(monkeypatch):
    def make(fail=False):
        monkeypatch.setattr(kyvern_anchor, "RFC3161Anchor", lambda *a, **k: FakeAnchor(fail=fail))
        monkeypatch.setattr(kyvern_anchor, "load_roots", lambda paths=None: [])
    return make


@pytest.fixture
def chain(tmp_path):
    path = tmp_path / "chain.jsonl"
    ChainWriter(path, ed25519.Ed25519PrivateKey.generate()).append({"n": 0})
    return path


def test_anchors_the_head_then_reports_it_is_already_anchored(chain, fake_tsa, capsys):
    fake_tsa()
    assert kyvern_anchor.main([str(chain)]) == 0
    assert "Anchored chain_index 0 at 2026-10-07T12:00:00Z via fake://tsa" in capsys.readouterr().out
    assert len(read_receipts(anchors_path_for(chain))) == 1

    assert kyvern_anchor.main([str(chain)]) == 0
    assert "Chain head 0 is already anchored" in capsys.readouterr().out
    assert len(read_receipts(anchors_path_for(chain))) == 1


def test_empty_chain_is_not_an_error(tmp_path, fake_tsa, capsys):
    fake_tsa()
    assert kyvern_anchor.main([str(tmp_path / "chain.jsonl")]) == 0
    assert "Nothing to anchor" in capsys.readouterr().out


def test_failure_exits_one(chain, fake_tsa, capsys):
    fake_tsa(fail=True)
    assert kyvern_anchor.main([str(chain)]) == 1
    assert "Anchoring failed: fake TSA is down" in capsys.readouterr().err
    assert not anchors_path_for(chain).exists()


def test_default_chain_comes_from_the_environment(chain, fake_tsa, monkeypatch, capsys):
    fake_tsa()
    monkeypatch.setenv("KYVERN_CHAIN_PATH", str(chain))
    assert kyvern_anchor.main([]) == 0
    assert "Anchored chain_index 0" in capsys.readouterr().out
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python -m pytest -q -p no:cacheprovider tests/cli/test_kyvern_anchor.py`
Expected: collection ERROR — `cannot import name 'kyvern_anchor' from 'cli'`.

- [ ] **Step 3: Create `cli/kyvern_anchor.py`**

```python
"""kyvern-anchor — timestamp the head of the audit chain with an RFC 3161 TSA.

Run it on a schedule (cron, Windows Task Scheduler, systemd timer). It never
touches the decision path: it only reads the chain and appends a receipt to
<chain stem>.anchors.jsonl.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from services.decision.anchors import AnchorError, anchor_head
from services.decision.chain_writer import AuditWriteError, last_entry
from services.decision.rfc3161_anchor import DEFAULT_TSA_URL, RFC3161Anchor, load_roots
from shared.paths import default_chain_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="kyvern-anchor",
        description="Timestamp the head of a Kyvern audit chain with an RFC 3161 Time Stamping Authority.",
    )
    parser.add_argument(
        "chain_file", nargs="?", default=None,
        help="audit chain JSONL (default: $KYVERN_CHAIN_PATH, else ~/.kyvern/chain.jsonl)",
    )
    parser.add_argument("--tsa-url", default=DEFAULT_TSA_URL, help=f"TSA endpoint (default: {DEFAULT_TSA_URL})")
    parser.add_argument(
        "--tsa-root", action="append", default=None,
        help="PEM file with trusted TSA root certificate(s); repeatable (default: certifi bundle)",
    )
    parser.add_argument("--timeout", type=float, default=30.0, help="seconds to wait for the TSA")
    args = parser.parse_args(argv)

    chain_path = Path(args.chain_file) if args.chain_file else default_chain_path()
    try:
        head = last_entry(chain_path)
        if head is None:
            print(f"Nothing to anchor: {chain_path} is empty")
            return 0
        anchor = RFC3161Anchor(args.tsa_url, roots=load_roots(args.tsa_root), timeout_s=args.timeout)
        receipt = anchor_head(chain_path, anchor)
    except (AnchorError, AuditWriteError, OSError, ValueError) as exc:
        print(f"Anchoring failed: {exc}", file=sys.stderr)
        return 1

    if receipt is None:
        print(f"Chain head {head['chain_index']} is already anchored")
    else:
        print(
            f"Anchored chain_index {receipt['chain_index']} at {receipt['anchored_at']} "
            f"via {receipt['tsa_url']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Register the command**

In `pyproject.toml` `[project.scripts]`, add after `kyvern-mcp = …`:

```toml
kyvern-anchor = "cli.kyvern_anchor:main"
```

Run: `python -m pip install -e . --no-deps -q` then `kyvern-anchor --help; "exit=$LASTEXITCODE"` → help text, `exit=0`.

- [ ] **Step 5: Run the tests**

Run: `python -m pytest -q -p no:cacheprovider tests/cli/test_kyvern_anchor.py` → `4 passed`.
Run: `python -m pytest -q -p no:cacheprovider` → `275 passed, 4 skipped`.

- [ ] **Step 6: Lint and commit**

Run: `python -m ruff check .` → `All checks passed!`

```bash
git add cli/kyvern_anchor.py pyproject.toml tests/cli/test_kyvern_anchor.py
git commit -m "feat: kyvern-anchor command"
```

---

### Task 4: `kyvern-verify` checks anchors

**Files:**
- Modify: `cli/kyvern_verify.py`
- Test: `tests/cli/test_kyvern_verify.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/cli/test_kyvern_verify.py` (`import shutil` at the top of the file):

```python
# ── anchors ──────────────────────────────────────────────────────────────────

RFC3161_FIXTURE = Path(__file__).parent.parent / "fixtures" / "rfc3161"


@pytest.fixture
def anchored(tmp_path):
    """A copy of the recorded fixture: 2-entry chain, receipt for entry 1, policy, keys."""
    for name in ("chain.jsonl", "chain.anchors.jsonl", "policy.yaml", "signing.pub", "signing.key"):
        shutil.copy(RFC3161_FIXTURE / name, tmp_path / name)
    clear_policy_cache()
    return tmp_path


def _verify_anchored(ws, *extra):
    return run_cli(
        str(ws / "chain.jsonl"), "--policy", str(ws / "policy.yaml"),
        "--pubkey", str(ws / "signing.pub"), *extra,
    )


def test_verify_reports_valid_anchors(anchored):
    res = _verify_anchored(anchored)
    assert res.returncode == 0, res.stdout
    assert "Anchors: 1 valid; latest covers chain_index 1" in res.stdout


def test_verify_fails_on_an_edited_receipt(anchored):
    receipts = anchored / "chain.anchors.jsonl"
    receipt = json.loads(receipts.read_text(encoding="utf-8"))
    receipt["payload_hash"] = "00" * 32
    receipts.write_text(json.dumps(receipt) + "\n", encoding="utf-8")
    res = _verify_anchored(anchored)
    assert res.returncode == 1
    assert "does not match the anchored hash" in res.stdout


def test_verify_without_receipts_says_none(anchored):
    (anchored / "chain.anchors.jsonl").unlink()
    res = _verify_anchored(anchored)
    assert res.returncode == 0, res.stdout
    assert "Anchors: none" in res.stdout


def test_verify_json_has_anchor_report(anchored):
    data = json.loads(_verify_anchored(anchored, "--json").stdout)
    assert data["anchors"]["valid"] == 1
    assert data["anchors"]["failures"] == []
    assert data["anchors"]["latest_index"] == 1
    assert data["anchors"]["unanchored_tail"] == 0


def test_rewrite_resigned_with_the_same_key_is_caught(anchored):
    """The keyholder rewrites anchored entry 1 and re-signs it: signatures pass, the anchor does not."""
    from services.decision.audit_chain import verify_chain

    key = serialization.load_pem_private_key((anchored / "signing.key").read_bytes(), password=None)
    chain_path = anchored / "chain.jsonl"
    entries = [json.loads(line) for line in chain_path.read_text(encoding="utf-8").splitlines()]
    rewritten = {k: v for k, v in entries[1].items() if k not in ("signature", "payload_hash", "key_id")}
    rewritten["reasoning"] = "rewritten after the incident"
    entries[1] = sign_decision(rewritten, prev_hash=entries[0]["payload_hash"], signing_key=key)
    chain_path.write_text("".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8")

    assert verify_chain(entries, key.public_key()) == (True, None)
    res = _verify_anchored(anchored)
    assert res.returncode == 1
    assert "Signature verification: PASSED" in res.stdout
    assert "does not match the anchored hash" in res.stdout
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python -m pytest -q -p no:cacheprovider tests/cli/test_kyvern_verify.py`
Expected: the 5 new tests fail (no anchors output; JSON has no `anchors`; the re-signed rewrite exits 0).

- [ ] **Step 3: Implement in `cli/kyvern_verify.py`**

(a) Imports — add after `import sys`:

```python
from dataclasses import asdict
from pathlib import Path
```

and after the `services.decision.audit_chain` import block:

```python
from services.decision.anchors import anchors_path_for, check_anchors, read_receipts
```

and after the `services.decision.policy_loader` import:

```python
from services.decision.rfc3161_anchor import RFC3161Anchor, load_roots
```

(b) Arguments — after the `--pubkey` argument:

```python
    parser.add_argument(
        "--anchors", default=None,
        help="anchor receipts JSONL (default: <chain stem>.anchors.jsonl next to the chain, if present)",
    )
    parser.add_argument(
        "--tsa-root", action="append", default=None,
        help="PEM file with trusted TSA root certificate(s); repeatable (default: certifi bundle)",
    )
```

(c) Replace `    all_valid = is_valid_chain and policy_matches` with:

```python
    anchors_path = Path(args.anchors) if args.anchors else anchors_path_for(Path(args.chain_file))
    anchor_report = None
    anchors_ok = True
    if anchors_path.exists():
        anchor_report = check_anchors(
            decisions,
            read_receipts(anchors_path),
            {RFC3161Anchor.name: RFC3161Anchor(roots=load_roots(args.tsa_root))},
        )
        for failure in anchor_report.failures:
            errors.append(f"Anchor check failed: {failure}")
        anchors_ok = not anchor_report.failures
    elif args.anchors:
        errors.append(f"Anchors file not found: {anchors_path}")
        anchors_ok = False

    all_valid = is_valid_chain and policy_matches and anchors_ok
```

(d) In the JSON `out` dict, add after `"reason": failure_reason,`:

```python
            "anchors": asdict(anchor_report) if anchor_report else None,
```

(e) After the `Signature verification` if/else block, add:

```python
    if anchor_report is None:
        print(f"  Anchors: none (no {anchors_path.name})")
    elif anchor_report.failures:
        print(f"{RED_CROSS} Anchors: FAILED")
        for failure in anchor_report.failures:
            print(f"  {failure}")
    else:
        line = f"{GREEN_CHECK} Anchors: {anchor_report.valid} valid"
        if anchor_report.latest_index is not None:
            line += (
                f"; latest covers chain_index {anchor_report.latest_index} at "
                f"{anchor_report.latest_time}; {anchor_report.unanchored_tail} later "
                "entries not yet anchored"
            )
        print(line)
```

- [ ] **Step 4: Run the tests**

Run: `python -m pytest -q -p no:cacheprovider tests/cli` → all pass.
Run: `python -m pytest -q -p no:cacheprovider` → `280 passed, 4 skipped`.

- [ ] **Step 5: Lint and commit**

Run: `python -m ruff check .` → `All checks passed!`

```bash
git add cli/kyvern_verify.py tests/cli/test_kyvern_verify.py
git commit -m "feat: kyvern-verify checks anchor receipts; a re-signed rewrite of an anchored entry fails"
```

---

### Task 5: Live check against IdenTrust

- [ ] **Step 1: Run the env-gated test**

```powershell
$env:KYVERN_TSA_E2E = "1"
python -m pytest -q -p no:cacheprovider tests/decision/test_rfc3161_anchor.py::test_live_identrust_timestamp
Remove-Item Env:KYVERN_TSA_E2E
```

Expected: `1 passed`.

- [ ] **Step 2: Run the real command end to end**

```powershell
$d = "<scratchpad>\anchor-demo"; New-Item -ItemType Directory -Force $d | Out-Null
Copy-Item tests\fixtures\rfc3161\chain.jsonl, tests\fixtures\rfc3161\policy.yaml, tests\fixtures\rfc3161\signing.pub $d
kyvern-anchor "$d\chain.jsonl"; "exit=$LASTEXITCODE"
kyvern-verify "$d\chain.jsonl" --policy "$d\policy.yaml" --pubkey "$d\signing.pub"; "exit=$LASTEXITCODE"
Remove-Item -Recurse -Force $d
```

Expected: `Anchored chain_index 1 at … via http://timestamp.identrust.com`, `exit=0`; then `✓ Anchors: 1 valid; latest covers chain_index 1 …`, `exit=0`.

No commit (nothing changes in the repo).

---

### Task 6: Documentation

**Files:** `docs/threat-model.md`, `docs/architecture.md`, `README.md`, `CHANGELOG.md`

- [ ] **Step 1: `docs/threat-model.md`**

Replace the bullet that starts `- **Still open: the keyholder.**` with:

```markdown
- **Anchoring the chain head.** `kyvern-anchor` sends the hash of the
  current chain head to an RFC 3161 Time Stamping Authority (IdenTrust by
  default) and stores the signed timestamp in `chain.anchors.jsonl`.
  `kyvern-verify` checks every receipt against the chain: an anchored entry
  that was rewritten — even re-signed with the right key — no longer matches
  its receipt and verification fails. Limits:
  - entries after the latest anchor can still be rewritten until the next
    `kyvern-anchor` run, so run it on a schedule (for example hourly);
  - the receipts file is the evidence: copy `chain.anchors.jsonl` off the
    host (log shipping, object storage), otherwise an attacker with host
    access can delete it;
  - the TSA receives only a hash, never chain contents.
```

- [ ] **Step 2: `docs/architecture.md`**

Insert before the line `The same chain also carries signed evidence events from external` (in §4):

```markdown
**Anchoring.** `kyvern-anchor` (`cli/kyvern_anchor.py`) timestamps the chain
head with an external authority. The statement it anchors is the canonical
JSON `{"chain_index": n, "kyvern_anchor": 1, "payload_hash": h}`; the receipt
goes to `<chain stem>.anchors.jsonl`. `services/decision/anchors.py` defines
the `Anchor` protocol (`name`, `request(statement)`, `verify(statement,
receipt)`); `services/decision/rfc3161_anchor.py` is the RFC 3161
implementation. Another kind of anchor implements the same two methods under
a new `name` and is added to the mapping `kyvern-verify` passes to
`check_anchors()`.
```

- [ ] **Step 3: `README.md`**

After the "Repeat `--pubkey` …" paragraph in "Verifying decisions", add:

````markdown
### Anchoring the chain

Run `kyvern-anchor` on a schedule to timestamp the chain head with an
external RFC 3161 authority (IdenTrust by default; `--tsa-url` and
`--tsa-root` to change it). `kyvern-verify` then checks the receipts and
fails if an anchored entry was rewritten, even by someone holding the
signing key.

```bash
# Linux/macOS, hourly (crontab -e)
0 * * * * kyvern-anchor /var/lib/kyvern/chain.jsonl
```

```bash
# Windows, hourly
schtasks /Create /SC HOURLY /TN "Kyvern anchor" /TR "kyvern-anchor C:\kyvern\chain.jsonl"
```
````

- [ ] **Step 4: `CHANGELOG.md`**

Append to `[Unreleased]` → `### Added`:

```markdown
- External anchoring of the chain head: `kyvern-anchor` stores RFC 3161
  timestamps (IdenTrust by default) in `<chain stem>.anchors.jsonl`;
  `kyvern-verify` checks them (`--anchors`, `--tsa-root`) and fails when an
  anchored entry was rewritten; generic `Anchor` protocol for other anchor
  types. New dependencies: `rfc3161-client`, `certifi`
```

- [ ] **Step 5: Check and commit**

Run: `python -m mkdocs build --strict -q -d <scratchpad>\site-check` → exit 0; then delete that directory.

```bash
git add docs/threat-model.md docs/architecture.md README.md CHANGELOG.md
git commit -m "docs: anchoring the chain head with RFC 3161 timestamps"
```

---

### Task 7: Acceptance, push and PR

- [ ] **Step 1:** `python -m pytest -q -p no:cacheprovider` → `280 passed, 4 skipped`; `python -m ruff check .` → clean.
- [ ] **Step 2:** Real `~/.kyvern` unchanged: compare with `<scratchpad>\kyvern_home_before.txt` using the hash listing command from the Part A plan.
- [ ] **Step 3:** In a throwaway venv with `--system-site-packages` and `pip install -e . --no-deps`: `kyvern-anchor --help` and `kyvern-verify --help` exit 0. Delete the venv.
- [ ] **Step 4:** Push and open the PR:

```bash
git push -u origin feat/anchoring
gh pr create --repo altunbulakemre75/kyvern --base main --head feat/anchoring --title "v0.3.0 part B: RFC 3161 anchoring of the chain head" --body-file <scratchpad>/pr_anchoring_body.md
```

`<scratchpad>/pr_anchoring_body.md`: summary (what `kyvern-anchor` does, receipts file, verify behaviour, `Anchor` protocol, IdenTrust default and why not DigiCert), test plan (counts from Step 1, recorded fixture, re-signed rewrite caught, live IdenTrust run from Task 5), and the line `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.

- [ ] **Step 5:** Report the PR link and CI result; merge only with the user's go-ahead.
