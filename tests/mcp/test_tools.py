import pytest
from mcp.server.fastmcp import FastMCP

from kernel.mcp.errors import KernelMCPError
from kernel.mcp.tools import register_tools


def _make_app(store, policy_path=None):
    app = FastMCP("kernel-test")
    register_tools(app, store, policy_path=policy_path)
    return app


def _call_tool(app, name, **kwargs):
    """Invoke a registered FastMCP tool synchronously and return the result."""
    tool = app._tool_manager.get_tool(name)
    fn = tool.fn
    return fn(**kwargs)


def test_query_events_filter_by_action(store):
    app = _make_app(store)
    result = _call_tool(app, "query_events", action="block")
    assert len(result) == 1
    assert result[0]["action"] == "block"
    assert "sig_valid" in result[0]


def test_query_events_filter_by_threat_level(store):
    app = _make_app(store)
    result = _call_tool(app, "query_events", threat_level="high")
    assert len(result) == 1
    assert result[0]["threat_level"] == "high"


def test_query_events_filter_by_time_range(store):
    app = _make_app(store)
    result = _call_tool(
        app,
        "query_events",
        start_time="2026-05-18T14:32:00+00:00",
        end_time="2026-05-18T14:32:30+00:00",
    )
    assert {e["id"] for e in result} == {0, 1}


def test_query_events_invalid_time_format(store):
    app = _make_app(store)
    with pytest.raises(KernelMCPError, match="invalid time format"):
        _call_tool(app, "query_events", start_time="not-iso")


def test_query_events_limit_out_of_range(store):
    app = _make_app(store)
    with pytest.raises(KernelMCPError, match="limit must be between"):
        _call_tool(app, "query_events", limit=0)


def test_get_event_clean_signature(store):
    app = _make_app(store)
    result = _call_tool(app, "get_event", event_id=0)
    assert result["sig_valid"] is True
    assert result["chain_link"] == "GENESIS"


def test_get_event_tampered_signature(store_tampered):
    app = _make_app(store_tampered)
    result = _call_tool(app, "get_event", event_id=1)
    assert result["sig_valid"] is False


def test_get_event_sig_valid_null_when_verify_disabled(store_unverified):
    app = _make_app(store_unverified)
    result = _call_tool(app, "get_event", event_id=0)
    assert result["sig_valid"] is None
    assert result["chain_link"] == "UNKNOWN"


def test_get_event_unknown_id_returns_none(store):
    app = _make_app(store)
    result = _call_tool(app, "get_event", event_id=999)
    assert result is None


def test_get_stats_window_24h(store):
    app = _make_app(store)
    result = _call_tool(app, "get_stats", window="24h")
    # Fixture has 3 events on day 1 (allow, block, flag) plus 1 on day 3
    assert sum(result["action_distribution"].values()) == 3
    assert result["chain_status"]["integrity"] == "OK"


def test_get_stats_window_all(store):
    app = _make_app(store)
    result = _call_tool(app, "get_stats", window="all")
    assert sum(result["action_distribution"].values()) == 4


def test_get_stats_invalid_window(store):
    app = _make_app(store)
    with pytest.raises(Exception, match="not-a-window|window|invalid"):  # noqa: B017
        _call_tool(app, "get_stats", window="not-a-window")


def test_verify_chain_clean(store):
    app = _make_app(store)
    result = _call_tool(app, "verify_chain")
    assert result["integrity"] == "OK"
    assert result["first_break"] is None


def test_verify_chain_tampered(store_tampered):
    app = _make_app(store_tampered)
    result = _call_tool(app, "verify_chain")
    assert result["integrity"] == "BROKEN"
    assert result["first_break"]["id"] == 1


def test_search_events_nested_field(store):
    app = _make_app(store)
    result = _call_tool(app, "search_events", query="10.0.0.7")
    assert len(result) >= 1
    assert any("10.0.0.7" in h["snippet"] for h in result)
