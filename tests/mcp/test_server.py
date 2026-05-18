import pytest

from kernel.mcp.errors import KernelMCPError
from kernel.mcp.server import build_app, parse_args


def test_parse_args_defaults():
    ns = parse_args([])
    assert ns.chain_file.endswith("chain.jsonl")
    assert ns.pubkey.endswith("signing.pub")
    assert ns.verify_on_query is True


def test_parse_args_no_verify():
    ns = parse_args(["--no-verify-on-query"])
    assert ns.verify_on_query is False


def test_build_app_starts(sample_chain_file, signing_keypair, tmp_path):
    _, _, pub_path = signing_keypair
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "rules:\n  - rule_id: r_001\n    description: t\n    when_threat_level: low\n    requires_operator_approval: false\n    action: log\n",
        encoding="utf-8",
    )
    app = build_app(
        chain_file=sample_chain_file,
        pubkey=pub_path,
        policy=policy,
        verify_on_query=True,
    )
    # Tools registered
    names = {t.name for t in app.list_tools_sync() if hasattr(app, "list_tools_sync")} \
        if hasattr(app, "list_tools_sync") else set(app._tool_manager._tools.keys())
    for expected in {"query_events", "get_event", "get_stats", "verify_chain", "search_events"}:
        assert expected in names, f"missing tool: {expected}"
    # Resources registered
    resources = set(app._resource_manager._resources.keys())
    for expected in {
        "kernel://audit/recent",
        "kernel://stats/today",
        "kernel://chain/status",
        "kernel://policy/active",
    }:
        assert expected in resources, f"missing resource: {expected}"


def test_build_app_chain_file_missing(tmp_path, signing_keypair):
    _, _, pub_path = signing_keypair
    missing = tmp_path / "nope.jsonl"
    with pytest.raises(KernelMCPError, match="chain file not found"):
        build_app(
            chain_file=missing,
            pubkey=pub_path,
            policy=None,
            verify_on_query=True,
        )


def test_build_app_pubkey_missing_with_verify(tmp_path, sample_chain_file):
    missing = tmp_path / "no-such-key.pub"
    with pytest.raises(KernelMCPError, match="public key not found"):
        build_app(
            chain_file=sample_chain_file,
            pubkey=missing,
            policy=None,
            verify_on_query=True,
        )


def test_build_app_pubkey_missing_with_no_verify_ok(tmp_path, sample_chain_file):
    # When verify-on-query=false, missing pubkey is acceptable
    app = build_app(
        chain_file=sample_chain_file,
        pubkey=tmp_path / "no-such-key.pub",
        policy=None,
        verify_on_query=False,
    )
    assert app is not None
