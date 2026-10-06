"""kernel.mcp.resources — register the 4 read-only resources on a FastMCP app."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from kernel.audit import AuditChainStore
from kernel.mcp.tools import _distributions, _summary


def _today_bounds() -> tuple[datetime, datetime]:
    now = datetime.now().astimezone()
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    end = start.replace(hour=23, minute=59, second=59, microsecond=999_999)
    return start, end


def register_resources(
    app: FastMCP,
    store: AuditChainStore,
    *,
    policy_path: Path | None = None,
) -> None:

    @app.resource("kernel://audit/recent", description="Last 100 audit events.")
    def recent() -> str:
        store.reload_if_stale()
        events = store.filter(limit=100)
        payload = [
            _summary(ev, store.verify_event(ev.get("chain_index", -1)))
            for ev in events
        ]
        return json.dumps(payload)

    @app.resource(
        "kernel://stats/today",
        description=(
            "Today's stats — server-host local-day boundaries (00:00–23:59:59 local TZ). "
            "Not a rolling 24-hour window."
        ),
    )
    def today() -> str:
        store.reload_if_stale()
        start, end = _today_bounds()
        events = store.filter(
            start_time=start.astimezone(timezone.utc),
            end_time=end.astimezone(timezone.utc),
            limit=10_000,
        )
        chain = store.verify_chain_range(None, None)
        payload = {
            **_distributions(events),
            "chain_status": {
                "verified": chain.verified_count,
                "total": chain.total_count,
                "integrity": chain.integrity,
            },
            "period": {
                "start": start.isoformat(),
                "end": end.isoformat(),
            },
        }
        return json.dumps(payload)

    @app.resource(
        "kernel://chain/status",
        description="Chain integrity verification result and chain length.",
    )
    def chain_status() -> str:
        store.reload_if_stale()
        chain = store.verify_chain_range(None, None)
        payload = {
            "verified_count": chain.verified_count,
            "total_count": chain.total_count,
            "first_break": chain.first_break,
            "integrity": chain.integrity,
            "chain_length": len(store.events()),
            "chain_file": str(store._chain_file),
        }
        return json.dumps(payload)

    @app.resource(
        "kernel://policy/active",
        description="Active policy metadata only — version_id, version_short, path, loaded_at. Body not exposed.",
    )
    def policy_active() -> str:
        if policy_path is None:
            return json.dumps({"error": "no policy configured — pass --policy"})
        if not Path(policy_path).exists():
            return json.dumps({"error": f"policy file not found at {policy_path}"})
        from services.decision.policy_loader import load_policy
        loaded = load_policy(str(policy_path))
        return json.dumps({
            "version_id": loaded.version_id,
            "version_short": loaded.version_short,
            "path": loaded.path,
            "loaded_at": loaded.loaded_at.isoformat(),
        })
