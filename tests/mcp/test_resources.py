import json
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from kyvern.mcp.resources import register_resources


def _make_app(store, policy_path=None):
    app = FastMCP("kyvern-test")
    register_resources(app, store, policy_path=policy_path)
    return app


def _resource_fn(app, uri):
    return app._resource_manager._resources[uri].fn


def test_resource_recent_returns_event_list(store):
    app = _make_app(store)
    payload = json.loads(_resource_fn(app, "kyvern://audit/recent")())
    assert isinstance(payload, list)
    assert payload[0]["id"] in {0, 1, 2, 3}


def test_resource_today_has_stats_shape(store):
    app = _make_app(store)
    payload = json.loads(_resource_fn(app, "kyvern://stats/today")())
    assert "action_distribution" in payload
    assert "threat_distribution" in payload
    assert "chain_status" in payload
    assert "period" in payload


def test_resource_recent_record_type_aware(store_mixed):
    app = _make_app(store_mixed)
    payload = json.loads(_resource_fn(app, "kyvern://audit/recent")())
    assert len(payload) == 4

    # Same shape as query_events summaries
    expected_keys = {
        "id", "timestamp_iso", "record_type", "action",
        "threat_level", "event_type", "source", "sig_valid",
    }
    assert all(set(e) == expected_keys for e in payload)
    assert all(e["sig_valid"] is True for e in payload)

    by_id = {e["id"]: e for e in payload}
    runtime = by_id[2]
    assert runtime["record_type"] == "runtime_event"
    assert runtime["action"] is None  # not ""
    assert runtime["threat_level"] is None
    assert runtime["event_type"] == "sensor_anomaly"
    assert runtime["source"] == "lidar_monitor"

    decision = by_id[1]
    assert decision["record_type"] == "decision"
    assert decision["action"] == "block"
    assert decision["event_type"] is None
    assert decision["source"] is None


def test_resource_today_record_type_aware(store_mixed, monkeypatch):
    day_start = datetime(2026, 5, 18, 0, 0, 0, tzinfo=timezone.utc)
    day_end = datetime(2026, 5, 18, 23, 59, 59, tzinfo=timezone.utc)
    monkeypatch.setattr(
        "kyvern.mcp.resources._today_bounds", lambda: (day_start, day_end)
    )
    app = _make_app(store_mixed)
    payload = json.loads(_resource_fn(app, "kyvern://stats/today")())
    assert payload["action_distribution"] == {"allow": 1, "block": 1}
    assert payload["threat_distribution"] == {"low": 1, "high": 1}
    assert payload["by_record_type"] == {"decision": 2, "runtime_event": 2}
    assert payload["by_event_type"] == {"sensor_anomaly": 1, "guardrail_downgrade": 1}


def test_resource_chain_status_integrity(store):
    app = _make_app(store)
    payload = json.loads(_resource_fn(app, "kyvern://chain/status")())
    assert payload["integrity"] == "OK"
    assert payload["chain_length"] == 4
    assert "chain_file" in payload


def test_resource_policy_active_metadata_only(store, tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "rules:\n  - rule_id: r_001\n    description: test\n    when_threat_level: low\n    requires_operator_approval: false\n    action: log\n",
        encoding="utf-8",
    )
    app = _make_app(store, policy_path=policy)
    payload = json.loads(_resource_fn(app, "kyvern://policy/active")())
    assert "version_id" in payload
    assert "version_short" in payload
    assert "loaded_at" in payload
    assert "path" in payload
    # Critical: body NEVER exposed
    assert "rules" not in payload
    assert "raw_bytes" not in payload


def test_resource_policy_active_missing_file(store, tmp_path):
    app = _make_app(store, policy_path=tmp_path / "does-not-exist.yaml")
    payload = json.loads(_resource_fn(app, "kyvern://policy/active")())
    assert "error" in payload
    assert "not found" in payload["error"]
