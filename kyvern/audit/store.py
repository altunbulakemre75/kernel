"""AuditChainStore — JSONL-backed read-only store for Kyvern decision audit chains."""
from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


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

    def load(self) -> None:
        if not self._chain_file.exists():
            from kyvern.mcp.errors import KyvernMCPError
            raise KyvernMCPError(f"chain file not found at {self._chain_file}")
        from services.decision.audit_chain import ChainFormatError, read_chain

        try:
            self._events = read_chain(self._chain_file)
        except ChainFormatError as exc:
            from kyvern.mcp.errors import KyvernMCPError
            raise KyvernMCPError(f"cannot read {self._chain_file}: {exc}") from exc
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
            from kyvern.mcp.errors import KyvernMCPError
            raise KyvernMCPError(f"chain file not found at {self._chain_file}") from None
        if self._mtime is None or current_mtime != self._mtime:
            self.load()

    def events(self) -> list[dict]:
        """Return a shallow copy of the event list.

        The list spine is fresh — callers cannot add or remove events from
        the store. The inner dicts are shared; treat them as read-only.
        """
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

    def verify_event(self, event_id: int) -> bool | None:
        if self._keyring is None or not self._verify_on_query:
            return None
        from services.decision.audit_chain import verify_decision
        ev = self.get(event_id)
        if ev is None:
            return None
        return verify_decision(ev, self._keyring)

    def verify_chain_range(
        self,
        start_id: int | None,
        end_id: int | None,
    ) -> ChainVerifyResult:
        if self._keyring is None or not self._verify_on_query:
            return ChainVerifyResult(
                verified_count=0,
                total_count=len(self._events),
                first_break=None,
                integrity="UNKNOWN",
            )
        if not self._events:
            return ChainVerifyResult(
                verified_count=0,
                total_count=0,
                first_break=None,
                integrity="UNKNOWN",
            )
        from services.decision.audit_chain import describe_chain_failure, verify_chain
        # In an intact chain an entry's chain_index is its position, so the range is
        # taken by position: an entry whose chain_index was removed or rewritten stays
        # in the range and fails it, instead of dropping out of it.
        start = 0 if start_id is None else max(start_id, 0)
        end = len(self._events) - 1 if end_id is None else end_id
        slice_events = self._events[start:end + 1] if end >= start else []
        if not slice_events:
            return ChainVerifyResult(
                verified_count=0,
                total_count=0,
                first_break=None,
                integrity="UNKNOWN",
            )
        # A range that does not start at genesis links to the entry just before it.
        prev_hash = self._events[start - 1].get("payload_hash") if start > 0 else None
        ok, broken_idx = verify_chain(slice_events, self._keyring, prev_hash=prev_hash)
        if ok:
            return ChainVerifyResult(
                verified_count=len(slice_events),
                total_count=len(slice_events),
                first_break=None,
                integrity="OK",
            )
        assert broken_idx is not None  # verify_chain names the failing entry
        broken_id = start + broken_idx
        return ChainVerifyResult(
            verified_count=broken_idx,
            total_count=len(slice_events),
            first_break={
                "id": broken_id,
                "reason": describe_chain_failure(
                    slice_events, broken_idx, self._keyring, prev_hash=prev_hash
                ),
            },
            integrity="BROKEN",
        )

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
            if len(results) >= limit:
                break
        return results


def _flatten_value(obj: Any) -> str:
    if isinstance(obj, dict):
        return " ".join(_flatten_value(v) for v in obj.values())
    if isinstance(obj, (list, tuple, set)):
        return " ".join(_flatten_value(v) for v in obj)
    return str(obj)
