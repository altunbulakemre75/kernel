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


def read_receipts(anchors_path: Path) -> list[Any]:
    """The receipts in a receipts file, one per non-empty line; None for a line that is
    not JSON. check_anchors() reports anything that is not a well-formed receipt."""
    path = Path(anchors_path)
    if not path.exists():
        return []
    receipts: list[Any] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            receipts.append(json.loads(line))
        except ValueError:
            receipts.append(None)
    return receipts


def _is_index(value: Any) -> bool:
    """A usable chain_index: an int, and not a bool (True == 1 in Python)."""
    return isinstance(value, int) and not isinstance(value, bool)


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
    if receipts and isinstance(receipts[-1], dict) and (
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
    receipts: list[Any],
    anchors: Mapping[str, Anchor],
) -> AnchorReport:
    """Check every receipt against the chain entries and its anchor.

    The receipts file is untrusted input: a receipt that is not an object with an
    integer chain_index and a payload_hash string is a failure, never an exception.
    """
    by_index = {e["chain_index"]: e for e in entries if _is_index(e.get("chain_index"))}
    valid = 0
    failures: list[str] = []
    latest: tuple[int, str | None] | None = None

    for i, receipt in enumerate(receipts):
        if not (
            isinstance(receipt, dict)
            and _is_index(receipt.get("chain_index"))
            and isinstance(receipt.get("payload_hash"), str)
        ):
            failures.append(
                f"receipt {i}: malformed (needs an integer chain_index and a payload_hash string)"
            )
            continue
        n: int = receipt["chain_index"]
        payload_hash: str = receipt["payload_hash"]
        anchor = anchors.get(str(receipt.get("anchor")))
        if anchor is None:
            failures.append(f"receipt {i}: unknown anchor type '{receipt.get('anchor')}'")
            continue
        entry = by_index.get(n)
        if entry is None:
            failures.append(f"receipt {i}: chain entry {n} is missing")
            continue
        result = anchor.verify(anchor_statement(n, payload_hash), receipt)
        if entry.get("payload_hash") != payload_hash:
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
        if latest_index is None
        or (_is_index(e.get("chain_index")) and e["chain_index"] > latest_index)
    )
    return AnchorReport(
        valid=valid,
        failures=failures,
        latest_index=latest_index,
        latest_time=latest[1] if latest else None,
        unanchored_tail=unanchored_tail,
    )
