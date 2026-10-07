# v0.3.0 Part B — External Anchoring of the Chain Head (RFC 3161)

**Date:** 2026-10-07
**Status:** Approved in conversation, awaiting review of this written spec
**Scope:** Periodically obtain an RFC 3161 timestamp over the current chain head from an external Time Stamping Authority (TSA), store the receipts next to the chain, and make `kyvern-verify` check them, behind a small generic `Anchor` interface so other anchor types can be added later.
**Out of scope:** Anchoring status in `kyvern-report` and `kyvern-mcp`; stamping with several TSAs at once; non-RFC 3161 anchors (blockchains, transparency logs) beyond the interface; anchoring from inside `ChainWriter` or the decision path.
**Builds on:** Part A (`ChainWriter`, `key_id`, `Keyring`), merged in `0d0d96a`.

---

## 1. Problem

Whoever holds the signing key can rewrite the chain from any point and re-sign it forward; nothing inside the chain proves that did not happen (raised in Issue #1, acknowledged in `docs/threat-model.md` → "Still open: the keyholder"). The public reply to Issue #1 committed to periodic external anchoring of the chain head, starting with RFC 3161 behind a generic hook, in v0.3.0.

An RFC 3161 timestamp is a signature by an independent TSA over a hash and a time. If the TSA has signed the hash of chain entry *n* at time *T*, a chain in which entry *n* has a different `payload_hash` was rewritten after *T*, regardless of who holds the Kyvern key.

## 2. Decisions

| Question | Choice |
|---|---|
| Where receipts live | A separate file next to the chain, `<chain stem>.anchors.jsonl` (for `chain.jsonl`: `chain.anchors.jsonl`). The chain format and every existing reader stay unchanged. Receipts are not signed by Kyvern; the TSA signature is what makes them evidence. |
| When anchoring happens | A separate command, `kyvern-anchor`, run on a schedule (cron, Windows Task Scheduler, systemd timer). The decision path never waits on the network. |
| Default TSA | IdenTrust, `http://timestamp.identrust.com`. Free, operated by a public CA, and its chain (TrustID Timestamp Authority → TrustID Timestamping CA 6 → IdenTrust Public Sector Root CA 1) verifies against the `certifi` bundle, so verification works without extra setup. Overridable with `--tsa-url` / `--tsa-root`. DigiCert was the first choice but is not usable with `rfc3161-client` — see §2.1. |
| Library | `rfc3161-client` (Trail of Bits, Apache-2.0, depends only on `cryptography`). Version `>=1.0.9`; versions before 1.0.3 did not verify the response signature against the leaf certificate (CVE-2025-52556). It does no network I/O; Kyvern sends the request with `urllib.request`. |
| Generic hook | A small `Anchor` protocol; every receipt names its anchor type (`"anchor": "rfc3161"`) and verification dispatches on it. |

### 2.1 TSA compatibility probe (2026-10-07)

Each TSA was sent one request for the hash of a throwaway statement, with a nonce and `certReq`, and the response was decoded and verified with `rfc3161-client` 1.0.9 against the `certifi` roots:

| TSA | Result |
|---|---|
| IdenTrust `http://timestamp.identrust.com` | parses and verifies with `certifi` roots |
| FreeTSA `https://freetsa.org/tsr`, Sigstore `https://timestamp.sigstore.dev/api/v1/timestamp` | parse; verify only when their own (self-signed) root is supplied with `--tsa-root` |
| DigiCert, Sectigo, GlobalSign, Entrust | rejected while parsing: `InvalidSetOrdering` in `SignedData::certificates` (their responses are not strict DER, and the library's parser is) |

`rfc3161-client` checks the certificate chain at the token's `genTime`, so receipts stay verifiable after the TSA certificate expires (IdenTrust's current TSA certificate runs to 2027-09-11).

## 3. What is anchored

```python
def anchor_statement(chain_index: int, payload_hash: str) -> bytes:
    return json.dumps(
        {"chain_index": chain_index, "kyvern_anchor": 1, "payload_hash": payload_hash},
        separators=(",", ":"), sort_keys=True,
    ).encode("utf-8")
```

The TSA timestamps the SHA-256 of this statement. Including `chain_index` makes the receipt say *which* entry it covers; `kyvern_anchor: 1` versions the statement format. The TSA receives only the hash, never chain contents.

## 4. Components

### 4.1 `services/decision/anchors.py` — interface, receipts file, checking

```python
class AnchorError(RuntimeError):
    """An anchor could not be obtained or did not verify."""

@dataclass(frozen=True)
class AnchorResult:
    ok: bool
    anchored_at: str | None   # ISO-8601 UTC time asserted by the anchor
    reason: str | None        # why ok is False

class Anchor(Protocol):
    name: str
    def request(self, statement: bytes) -> dict[str, Any]: ...
        # anchor-specific receipt fields (must include "anchored_at"); raises AnchorError
    def verify(self, statement: bytes, receipt: dict[str, Any]) -> AnchorResult: ...

def anchors_path_for(chain_path: Path) -> Path: ...        # chain.jsonl -> chain.anchors.jsonl
def read_receipts(anchors_path: Path) -> list[dict[str, Any]]: ...
def append_receipt(anchors_path: Path, receipt: dict[str, Any]) -> None: ...
    # FileLock(<anchors_path>.lock) + one JSON line + flush + fsync
def anchor_head(chain_path: Path, anchor: Anchor) -> dict[str, Any] | None: ...

@dataclass(frozen=True)
class AnchorReport:
    valid: int
    failures: list[str]           # one human-readable line per bad receipt
    latest_index: int | None      # highest chain_index covered by a valid receipt
    latest_time: str | None
    unanchored_tail: int          # chain entries after latest_index

def check_anchors(entries: list[dict], receipts: list[dict],
                  anchors: Mapping[str, Anchor]) -> AnchorReport: ...
```

A receipt line is:

```json
{"anchor": "rfc3161", "chain_index": 4810, "payload_hash": "<hex>",
 "anchored_at": "2026-10-07T10:00:03Z", "tsa_url": "http://timestamp.identrust.com",
 "token": "<base64 DER TimeStampResp>"}
```

`anchor_head(chain_path, anchor)`:
1. Read the last chain entry (reusing `chain_writer._last_entry`, which already rejects a corrupt tail). Empty or missing chain → return `None`.
2. If the last receipt in the anchors file has the same `chain_index` and `payload_hash`, return `None` (already anchored).
3. `anchor.request(anchor_statement(...))`, add `anchor`, `chain_index`, `payload_hash`, `append_receipt`, return the receipt.

It does not hold the chain lock while talking to the TSA; the receipt names the exact entry it covers, so later appends do not matter.

`check_anchors()` rules, per receipt:
- Unknown `anchor` type → failure `"receipt <i>: unknown anchor type '<name>'"`.
- No chain entry with that `chain_index` → failure `"receipt <i>: chain entry <n> is missing"`.
- Entry exists but its `payload_hash` differs → failure `"receipt <i>: chain entry <n> does not match the anchored hash (rewritten after <anchored_at>?)"`.
- `anchor.verify(anchor_statement(receipt chain_index, receipt payload_hash), receipt)` not ok → failure `"receipt <i>: <reason>"`.
- Otherwise valid. `latest_index` / `latest_time` come from the valid receipt with the highest `chain_index`; `latest_time` is the `anchored_at` returned by `verify()` (read from the signed token), never the unsigned `anchored_at` field stored in the receipt line. `unanchored_tail` counts entries with a higher `chain_index`.

### 4.2 `services/decision/rfc3161_anchor.py`

```python
DEFAULT_TSA_URL = "http://timestamp.identrust.com"

class RFC3161Anchor:
    name = "rfc3161"
    def __init__(self, tsa_url: str = DEFAULT_TSA_URL,
                 roots: list[x509.Certificate] | None = None,   # default: certifi bundle
                 timeout_s: float = 30.0) -> None: ...
    def request(self, statement: bytes) -> dict[str, Any]: ...
    def verify(self, statement: bytes, receipt: dict[str, Any]) -> AnchorResult: ...
```

- `request()`: build the request with `TimestampRequestBuilder().data(statement)` (SHA-256, nonce, certificate requested); POST it with `urllib.request` (`Content-Type: application/timestamp-query`, `timeout_s`); `decode_timestamp_response`; then **verify the response immediately with `verify()` and raise `AnchorError` if it does not verify**, so an unverifiable receipt is never stored. Returns `{"tsa_url", "token", "anchored_at"}`; `anchored_at` is the TSA's `genTime` in UTC.
- `verify()`: decode the token, check it covers `statement` (`verify_message`) and chains to one of `roots`. The default roots come from `certifi.where()`. Any decoding or verification error gives `AnchorResult(ok=False, anchored_at=None, reason="timestamp does not verify: <detail>")`; `verify()` never raises.
- Network, HTTP and decoding errors are raised as `AnchorError` with the original as `__cause__`.

### 4.3 `kyvern-anchor` — new `cli/kyvern_anchor.py`

```
kyvern-anchor [CHAIN_FILE] [--tsa-url URL] [--tsa-root PEM ...] [--timeout SECONDS]
```

- `CHAIN_FILE` defaults to `shared.paths.default_chain_path()` (same resolution as `ChainWriter` and `kyvern-mcp`).
- Prints one line and exits:
  - anchored → `Anchored chain_index <n> at <anchored_at> via <tsa_url>`, exit 0
  - already anchored → `Chain head <n> is already anchored`, exit 0
  - empty chain → `Nothing to anchor: <path> is empty`, exit 0
  - any `AnchorError` / `AuditWriteError` → `Anchoring failed: <reason>` on stderr, exit 1 (so the scheduler can alert)
- Registered in `pyproject.toml` as `kyvern-anchor = "cli.kyvern_anchor:main"`.

### 4.4 `kyvern-verify`

- New options: `--anchors PATH` (default: `anchors_path_for(chain_file)` if that file exists) and `--tsa-root PEM` (repeatable; default: certifi bundle).
- When a receipts file is present, run `check_anchors()` with `{"rfc3161": RFC3161Anchor(roots=...)}`.
- Human output, after the signature line:
  - `✓ Anchors: 12 valid; latest covers chain_index 4810 at 2026-10-07T10:00:03Z; 37 later entries not yet anchored`
  - `✗ Anchors: FAILED` followed by each failure line
  - `Anchors: none (no <path>)` when there is no receipts file — not a failure.
- JSON output gains `"anchors": null` or `{"valid", "failures", "latest_index", "latest_time", "unanchored_tail"}`.
- Exit code 1 if any receipt fails, in addition to today's conditions.

## 5. Dependencies

`requirements.txt`: add `rfc3161-client>=1.0.9` and `certifi` (already present transitively through `httpx`; listed because Kyvern now uses it directly).

## 6. Tests

No test contacts the network by default.

- **Statement:** deterministic bytes; different `chain_index` or `payload_hash` gives different bytes.
- **Receipts file:** `anchors_path_for`; append then read round-trips; each append is fsynced.
- **`anchor_head` with a fake `Anchor`** (records the statements it was asked to anchor; `verify` returns ok): anchors the head; second call without new entries returns `None` and does not call the anchor; after a new chain entry it anchors again; empty chain returns `None`; an `AnchorError` from the anchor propagates and writes nothing.
- **`check_anchors` with the fake anchor:** all valid → counts, `latest_index`, `unanchored_tail`; rewritten entry (same index, different `payload_hash`) → failure mentioning "does not match"; missing entry → failure; unknown anchor type → failure; fake `verify` returning not ok → failure with its reason.
- **Recorded fixture** (`tests/fixtures/rfc3161/`), created once during implementation by a small script and committed: a test-only Ed25519 key pair (`signing.key`, `signing.pub`), a two-entry `chain.jsonl` signed with it, and `chain.anchors.jsonl` holding a real IdenTrust receipt for entry 1. Recording sends IdenTrust only the hash of that test statement. All tests below use these files offline.
- **`RFC3161Anchor.verify`:** the fixture receipt verifies with the default roots and returns IdenTrust's `genTime`; it fails for a different statement; it fails with an empty root list; a corrupted token gives `ok=False` with a reason starting `"timestamp does not verify"`, not an exception.
- **`RFC3161Anchor.request` without network:** `urllib.request.urlopen` patched to return the fixture token → returns the receipt fields; patched to raise → `AnchorError`; asked to anchor a different statement while returning the fixture token → `AnchorError` (immediate verification).
- **`kyvern-anchor` CLI** (in-process `main()` with `sys.argv` patched and `RFC3161Anchor` replaced by the fake): exit 0 and one receipt line; second run prints "already anchored"; empty chain exit 0; failing anchor exit 1 with "Anchoring failed".
- **`kyvern-verify`** (subprocess, like the existing CLI tests, on copies of the fixture): exit 0 and "Anchors: 1 valid"; receipt `payload_hash` edited → exit 1 and "does not match"; no receipts file → "Anchors: none" and exit 0; JSON output has the `anchors` object.
- **Rewrite with the same key is caught:** change entry 1 of the fixture chain and re-sign entries 1.. with the fixture private key, so `verify_chain` passes; `kyvern-verify` still exits 1 because entry 1 no longer matches the anchored hash.
- **Live IdenTrust test**, skipped unless `KYVERN_TSA_E2E=1`: `kyvern-anchor` on a temp chain against IdenTrust, then `kyvern-verify` passes.

## 7. Documentation

- `docs/threat-model.md`, "Still open: the keyholder" becomes "Anchoring the chain head": anchored entries cannot be rewritten without contradicting a TSA-signed receipt; entries after the latest anchor can still be rewritten until the next run; the receipts file must survive, so copy `chain.anchors.jsonl` off the host (log shipping, object storage); the TSA sees only a hash.
- `docs/architecture.md`: anchoring section (statement, receipts file, `Anchor` interface and how to add one).
- `README.md`: `kyvern-anchor` usage with an hourly cron line and a Windows Task Scheduler (`schtasks`) line; `kyvern-verify` anchors output.
- `CHANGELOG.md` `[Unreleased]` → Added.

## 8. Acceptance criteria

- All existing tests pass (251 passed, 3 skipped before this work) plus the new ones; `ruff check .` clean; CI green on Python 3.10–3.12.
- With `KYVERN_TSA_E2E=1` on the dev machine: `kyvern-anchor` obtains an IdenTrust timestamp for a temp chain and `kyvern-verify` reports it valid.
- Tampering with an anchored entry (rewriting and re-signing the chain with the same key) makes `kyvern-verify` fail with "does not match the anchored hash" — demonstrated by the fixture test in §6.
- The real `~/.kyvern` is unchanged after the suite.

## 9. Delivery

Branch `feat/anchoring` from `main` (`0d0d96a`). One commit per plan task. Claude opens the PR; merging needs the user's go-ahead. After it lands, Claude drafts an update for Issue #1 and posts it only with the user's explicit approval. v0.3.0 is tagged only when the user says so.
