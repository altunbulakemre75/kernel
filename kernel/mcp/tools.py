"""kernel.mcp.tools — register the 5 read-only tools on a FastMCP app."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

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
    policy_path: Path | None = None,  # reserved for future policy-enforcement hooks
) -> None:
    del policy_path  # unused today; callers may pass it for forward-compatibility

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
        events = store.filter(start_time=start, end_time=now if window != "all" else None, limit=10_000)
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
