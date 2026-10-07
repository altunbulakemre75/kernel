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
