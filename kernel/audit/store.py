"""AuditChainStore — JSONL-backed read-only store for kernel decision audit chains."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


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
