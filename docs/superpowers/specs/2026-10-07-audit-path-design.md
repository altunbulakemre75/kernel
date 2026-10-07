# v0.3.0 Part A — One Verifiable Audit Chain

**Date:** 2026-10-07
**Status:** Approved in conversation, awaiting review of this written spec
**Scope:** Make every decision from the live pipeline land in the same signed JSONL chain that `kyvern-verify`, `kyvern-report` and `kyvern-mcp` read; write it safely from several processes on one host; refuse to return a decision that could not be recorded; record which key signed each entry and verify chains signed by more than one key.
**Out of scope:** External anchoring of the chain head (RFC 3161 behind a generic hook) is Part B, specified separately and built on top of this. Also out of scope: a Postgres backend, several hosts writing one chain, a key-rotation command, and the rule-only `decide()` shim (it stays a non-recording test/CLI helper, as documented today).

---

## 1. Problem

Findings from reading the code on 2026-10-07:

1. **Decisions never reach the verifiable chain.** `llm_graph.finalize` writes decisions only to Postgres (`KYVERN_DB_DSN`), or nowhere if that is unset. `kyvern-verify`, `kyvern-report` and `kyvern-mcp` read only the JSONL chain, where only RuntimeEvents (and the demo script) write. Without a DSN every decision is signed with `chain_index` 0 and no `prev_hash`, so there is no chain at all.
2. **No locking.** Both `append_runtime_event` and `finalize` read the last entry and then append. Two concurrent writers get the same `prev_hash` and index, and the chain forks silently.
3. **Postgres rows cannot be re-verified.** The table omits signed fields (for example `guardrail_reasoning`) and converts `timestamp_iso` to `TIMESTAMPTZ`, so the signed canonical JSON cannot be rebuilt from a row.
4. **Fail-open.** Every write and signing error in `finalize` is logged as a warning and the decision is returned anyway.
5. **No key identity.** Records do not say which key signed them, so a key change, deliberate or accidental, cannot be told apart from tampering, and `load_or_create_keypair()` mints a new key whenever none is found.

## 2. Decisions

| Question | Choice |
|---|---|
| Single source of truth | The JSONL chain file. Postgres writing is removed. |
| Several writers | Shared file plus an OS-level file lock (`filelock` package), on one host. |
| Recording fails | `run_graph()` raises `AuditWriteError`; no decision is returned. |
| Key identity | Every record carries a signed `key_id`; verifiers accept several public keys and pick the right one per record. Rotation is a documented manual procedure, not a command. |

## 3. Components

### 3.1 `key_id` — `services/decision/audit_chain.py`

```python
def key_id(public_key: Ed25519PublicKey) -> str:
    """First 16 hex chars of SHA-256 over the raw 32-byte public key."""
```

`sign_decision()` sets `record["key_id"] = key_id(signing_key.public_key())` before canonicalising, so `key_id` is covered by the signature and `payload_hash`. This applies to every caller (chain writer, RuntimeEvents, `InMemoryAuditStore`, tests). `Decision` and `RuntimeEvent` get a new optional field `key_id: str | None = None` so the value survives `Decision(**signed)` / `RuntimeEvent(**signed)`.

### 3.2 `Keyring` and key-aware verification — `services/decision/audit_chain.py`

```python
class Keyring:
    @classmethod
    def from_pem_files(cls, paths: Iterable[str | Path]) -> "Keyring": ...
    def get(self, key_id: str) -> Ed25519PublicKey | None: ...
    def ids(self) -> list[str]: ...
    def __iter__(self) -> Iterator[Ed25519PublicKey]: ...
```

`verify_decision(record, keys)` and `verify_chain(records, keys)` accept either a single `Ed25519PublicKey` (existing callers keep working) or a `Keyring`:

| Record has `key_id`? | Single key given | Keyring given |
|---|---|---|
| yes | valid only if `key_id(key)` matches and the signature verifies | look up `key_id`; unknown id → invalid |
| no (pre-0.3.0 record) | verify with that key | valid if any key in the keyring verifies it |

`verify_chain` keeps its return type `(ok, first_bad_index)`. A new helper `describe_chain_failure(records, index, keys) -> str` explains why `records[index]` failed, using the previous record for link checks: `"chain_index gap"`, `"broken prev_hash link"`, `"signed by unknown key <key_id>"` or `"bad signature"`. The CLIs and MCP use it for their output.

### 3.3 Chain writer — new `services/decision/chain_writer.py`

```python
class AuditWriteError(RuntimeError):
    """A record could not be durably appended to the chain."""

class ChainWriter:
    def __init__(self, chain_path: Path, signing_key: Ed25519PrivateKey,
                 lock_timeout_s: float = 10.0): ...

    @classmethod
    def open(cls, chain_path: Path | None = None) -> "ChainWriter":
        """Resolve the chain path and the signing key (see §3.4)."""

    def append(self, record: dict) -> dict:
        """Sign `record` as the next entry and durably append it; return the signed dict."""
```

`append()` does, while holding `FileLock(<chain_path>.lock, timeout=lock_timeout_s)`:

1. Create the parent directory if needed.
2. Read the last non-empty line by seeking from the end of the file (not reading the whole file). If it does not parse as JSON, or lacks `payload_hash` / `chain_index`, raise `AuditWriteError("chain tail is corrupt …; run kyvern-verify")` and write nothing.
3. Overwrite the chain fields on a copy of `record`: drop caller `signature` / `payload_hash` / `key_id`, set `chain_index = last.chain_index + 1` (or 0) and `prev_hash = last.payload_hash` (or `None`).
4. `sign_decision()` the copy.
5. Write one line `json.dumps(signed, separators=(",", ":"))` + `"\n"`, then `flush()` and `os.fsync()`.

Any exception in steps 1–5 (lock timeout, I/O error, signing error) is raised as `AuditWriteError` with the original as `__cause__`. The stored line is exactly the signed record, so every entry can be re-verified from the file alone.

### 3.4 Chain path and key resolution

- Chain path: the `chain_path` argument; else `KYVERN_CHAIN_PATH`; else `kyvern_home() / "chain.jsonl"`. One function, `shared.paths.default_chain_path()`, implements the last two steps, and both `ChainWriter.open()` and the `kyvern-mcp` `--chain-file` default use it, so the writer and the reader always agree.
- Signing key: `kyvern_home() / "keys" / "signing.key"` as today, through `load_or_create_keypair()`, with one new rule in `ChainWriter.open()`: **if the key file is missing and the chain already has at least one entry, raise `AuditWriteError("refusing to create a new signing key for an existing chain …")`** instead of minting a key. A new key is only created for an empty or missing chain. Rotating keys is the manual procedure in §6.

### 3.5 Live pipeline — `services/decision/llm_graph.py`

- `run_graph(..., chain_path: Path | None = None)` gains the parameter and threads it through `GraphState`.
- `finalize` drops all Postgres code. It sets `policy_version_id` / `policy_path` as today, calls `ChainWriter.open(state.chain_path).append(state.decision.model_dump())`, and replaces `state.decision` with `Decision(**signed)`. It does not catch `AuditWriteError`, so `run_graph()` raises it (both the LangGraph path and the sequential fallback).
- `decide_full()` passes `chain_path` through.
- `asyncpg` is removed from `requirements.txt` (its only use was here); `KYVERN_DB_DSN` / `NIZAM_DB_DSN` are no longer read.

### 3.6 RuntimeEvents — `append_runtime_event()`

Keeps its signature and security contract (caller chain fields are discarded) and delegates to `ChainWriter(chain_path, signing_key).append(...)`, so it gains the lock, the tail check, `fsync` and `key_id`. It raises `AuditWriteError` on failure.

### 3.7 Readers

- `kyvern-verify` and `kyvern-report`: `--pubkey` becomes repeatable (`action="append"`, still required at least once) and builds a `Keyring`. Failures are reported with `describe_chain_failure()`. The JSON output of `kyvern-verify` gains `"key_ids": [...]` (ids seen in the chain) and, on failure, `"reason"`. The report's key fingerprint section lists the `key_id`s of the supplied keys (same definition as §3.1) instead of a hash of the PEM file.
- `kyvern-mcp` / `AuditChainStore`: `--pubkey` repeatable with default `[kyvern_home()/keys/signing.pub]`; the store takes `public_key_paths: list[Path] | None` and verifies with a `Keyring`. `verify_chain` tool output gains `reason` on failure.
- ROS2 subscriber example and `InMemoryAuditStore.verify()`: unchanged API; they pass a single key, which §3.2 still supports.

## 4. Behaviour changes (CHANGELOG, breaking)

- `run_graph()` / `decide_full()` raise `AuditWriteError` when the decision cannot be recorded; they previously returned it anyway.
- Decisions are recorded in the JSONL chain (default `~/.kyvern/chain.jsonl`, override with `chain_path=` or `KYVERN_CHAIN_PATH`). Postgres recording and `KYVERN_DB_DSN` are removed.
- New records carry `key_id`. Chains containing them need this version to verify; older records still verify.
- The signing key is no longer auto-created next to a non-empty chain.

## 5. Tests

Written before the code they cover.

- **Writer:** first entry has index 0 and no `prev_hash`; second links to the first; `key_id` matches the key; `os.fsync` is called once per append; caller-supplied chain fields are overwritten; a corrupt last line raises `AuditWriteError` and leaves the file byte-for-byte unchanged; a lock held elsewhere past the timeout raises `AuditWriteError`.
- **Concurrency:** 4 processes × 25 appends to one file → 100 lines, `chain_index` exactly 0–99, `verify_chain` passes.
- **Key rules:** `ChainWriter.open()` with a non-empty chain and no key file raises and creates no key; with an empty chain it creates one.
- **Live pipeline:** `run_graph()` appends one decision per call to the given `chain_path`; `kyvern-verify` accepts the resulting file (the end-to-end "live decisions are verifiable" test); with an unwritable `chain_path`, `run_graph()` raises `AuditWriteError`.
- **Keyring:** a chain signed by two keys verifies with both public keys; with only one, verification fails at the first record of the other key with reason "signed by unknown key"; a record without `key_id` verifies against a single key and against a keyring containing it.
- **CLIs:** `kyvern-verify` with two `--pubkey` flags; JSON output includes `key_ids`; `kyvern-mcp` accepts two `--pubkey` flags; with `KYVERN_CHAIN_PATH` set, `kyvern-mcp`'s `--chain-file` default and `ChainWriter.open()` resolve to the same file.
- **Failure reasons:** `describe_chain_failure()` returns each of its four reasons for a chain built to trigger it.
- **Hermetic tests:** an autouse fixture in `tests/conftest.py` points `Path.home()` at a per-test temporary directory, so no test reads or writes the developer's real `~/.kyvern` (today the suite writes a real signing key there; after this change it would also append decisions to the real chain). Existing tests that rely on `run_graph` keep passing with that fixture.

## 6. Documentation

- `docs/threat-model.md`: what is now guaranteed (no unrecorded decision leaves `run_graph`; one host, many processes; every entry names its key) and what still is not (the keyholder can rewrite and re-sign the chain until Part B anchors the head externally; several hosts writing one chain).
- Key rotation procedure (in the threat model or architecture doc): stop writers; copy `signing.pub` to an archive name that includes its `key_id`; generate a new key pair with the documented Python snippet into `~/.kyvern/keys/`; restart writers; verify with both public keys.
- `docs/architecture.md`, `README.md`: recording path, `chain_path` / `KYVERN_CHAIN_PATH`, repeatable `--pubkey`, removal of `KYVERN_DB_DSN`.
- `CHANGELOG.md` `[Unreleased]`: §4.

## 7. Acceptance criteria

- All existing tests pass (221 passed, 3 skipped before this work) plus the new ones; `ruff check .` is clean.
- The end-to-end test in §5 passes: a decision produced by `run_graph()` is verified by `kyvern-verify`.
- The concurrency test passes on Windows locally and on Linux in CI (Python 3.10–3.12).
- After the full test suite runs, the developer's real `~/.kyvern` is unchanged (same files, same `signing.pub` hash).
- No reference to `asyncpg` or `KYVERN_DB_DSN` remains outside `docs/superpowers/` and the CHANGELOG.

## 8. Delivery

Branch `feat/audit-path` from `main` (`67788ce`). One commit per plan task. Claude opens the PR; the user merges. No version bump or tag: v0.3.0 is tagged only after Part B, and only when the user says so.
