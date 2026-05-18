import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from kernel.mcp.resources import register_resources


def _make_app(store, policy_path=None):
    app = FastMCP("kernel-test")
    register_resources(app, store, policy_path=policy_path)
    return app


def _resource_fn(app, uri):
    return app._resource_manager._resources[uri].fn


def test_resource_recent_returns_event_list(store):
    app = _make_app(store)
    payload = json.loads(_resource_fn(app, "kernel://audit/recent")())
    assert isinstance(payload, list)
    assert payload[0]["id"] in {0, 1, 2, 3}


def test_resource_today_has_stats_shape(store):
    app = _make_app(store)
    payload = json.loads(_resource_fn(app, "kernel://stats/today")())
    assert "action_distribution" in payload
    assert "threat_distribution" in payload
    assert "chain_status" in payload
    assert "period" in payload


def test_resource_chain_status_integrity(store):
    app = _make_app(store)
    payload = json.loads(_resource_fn(app, "kernel://chain/status")())
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
    payload = json.loads(_resource_fn(app, "kernel://policy/active")())
    assert "version_id" in payload
    assert "version_short" in payload
    assert "loaded_at" in payload
    assert "path" in payload
    # Critical: body NEVER exposed
    assert "rules" not in payload
    assert "raw_bytes" not in payload


def test_resource_policy_active_missing_file(store, tmp_path):
    app = _make_app(store, policy_path=tmp_path / "does-not-exist.yaml")
    payload = json.loads(_resource_fn(app, "kernel://policy/active")())
    assert "error" in payload
    assert "not found" in payload["error"]
