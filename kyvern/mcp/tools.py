"""kyvern.mcp.tools — register the 5 read-only tools on a FastMCP app."""
# No `from __future__ import annotations` here: older FastMCP (e.g. mcp 1.12) calls
# issubclass() on tool parameter annotations and crashes on string annotations.

from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from kyvern.audit import AuditChainStore
from kyvern.mcp.errors import KyvernMCPError


def _parse_iso(value: str | None, field: str) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise KyvernMCPError(
            f"invalid time format for '{field}' — expected ISO 8601, "
            f"e.g. 2026-05-18T14:32:07Z"
        ) from exc


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


def _distributions(events: list[dict]) -> dict[str, dict[str, int]]:
    """Action/threat counts cover Decisions only; RuntimeEvents are counted by event_type."""
    actions: Counter[str] = Counter()
    threats: Counter[str] = Counter()
    record_types: Counter[str] = Counter()
    event_types: Counter[str] = Counter()
    for ev in events:
        record_type = ev.get("record_type", "decision")
        record_types[record_type] += 1
        if record_type == "decision":
            actions[ev.get("action", "unknown")] += 1
            if ev.get("threat_level"):
                threats[ev["threat_level"]] += 1
        elif record_type == "runtime_event":
            event_types[ev.get("event_type", "unknown")] += 1
    return {
        "action_distribution": dict(actions),
        "threat_distribution": dict(threats),
        "by_record_type": dict(record_types),
        "by_event_type": dict(event_types),
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
            raise KyvernMCPError("limit must be between 1 and 1000")
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
            raise KyvernMCPError(
                "window must be one of: 1h, 24h, 7d, 30d, all"
            )
        store.reload_if_stale()
        now = datetime.now(timezone.utc)
        start = _window_to_start(window, now)
        events = store.filter(start_time=start, end_time=now if window != "all" else None, limit=10_000)
        chain_result = store.verify_chain_range(None, None)
        return {
            **_distributions(events),
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
            raise KyvernMCPError("limit must be between 1 and 500")
        store.reload_if_stale()
        hits = store.search(query, limit=limit)
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
