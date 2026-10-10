from pathlib import Path

import pytest

pytest.importorskip("mcp")  # the mcp extra

from kyvern.mcp.errors import KyvernMCPError
from kyvern.mcp.server import build_app, parse_args


def test_parse_args_defaults(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    ns = parse_args([])
    assert Path(ns.chain_file) == tmp_path / ".kyvern" / "chain.jsonl"
    assert [Path(p) for p in ns.pubkey] == [tmp_path / ".kyvern" / "keys" / "signing.pub"]
    assert ns.verify_on_query is True


def test_parse_args_no_verify(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
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
        "kyvern://audit/recent",
        "kyvern://stats/today",
        "kyvern://chain/status",
        "kyvern://policy/active",
    }:
        assert expected in resources, f"missing resource: {expected}"


def test_build_app_chain_file_missing(tmp_path, signing_keypair):
    _, _, pub_path = signing_keypair
    missing = tmp_path / "nope.jsonl"
    with pytest.raises(KyvernMCPError, match="chain file not found"):
        build_app(
            chain_file=missing,
            pubkey=pub_path,
            policy=None,
            verify_on_query=True,
        )


def test_build_app_pubkey_missing_with_verify(tmp_path, sample_chain_file):
    missing = tmp_path / "no-such-key.pub"
    with pytest.raises(KyvernMCPError, match="public key not found"):
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


def test_parse_args_accepts_several_pubkeys():
    ns = parse_args(["--pubkey", "a.pub", "--pubkey", "b.pub"])
    assert ns.pubkey == ["a.pub", "b.pub"]


def test_chain_default_matches_the_writer(tmp_path, monkeypatch):
    from services.decision.chain_writer import ChainWriter

    target = tmp_path / "shared.jsonl"
    monkeypatch.setenv("KYVERN_CHAIN_PATH", str(target))
    ChainWriter.open().append({"n": 1})
    assert Path(parse_args([]).chain_file) == target


def test_build_app_with_two_pubkeys(sample_chain_file, signing_keypair, tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    _, _, pub_path = signing_keypair
    other = tmp_path / "other.pub"
    other.write_bytes(ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    app = build_app(
        chain_file=sample_chain_file, pubkey=[pub_path, other],
        policy=None, verify_on_query=True,
    )
    assert app is not None


def test_run_reports_a_bad_key_without_a_traceback(sample_chain_file, tmp_path, monkeypatch, capsys):
    import sys

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from kyvern.mcp.server import run

    p256 = tmp_path / "p256.pub"
    p256.write_bytes(ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    monkeypatch.setattr(sys, "argv", [
        "kyvern-mcp", "--chain-file", str(sample_chain_file), "--pubkey", str(p256),
    ])
    with pytest.raises(SystemExit) as exc:
        run()
    assert exc.value.code == 1
    assert "kyvern-mcp: " in capsys.readouterr().err


def test_run_reports_a_bad_chain_line_without_a_traceback(sample_chain_file, signing_keypair, monkeypatch, capsys):
    import sys

    from kyvern.mcp.server import run

    _, _, pub_path = signing_keypair
    with open(sample_chain_file, "a", encoding="utf-8") as f:
        f.write("[1, 2]\n")
    monkeypatch.setattr(sys, "argv", [
        "kyvern-mcp", "--chain-file", str(sample_chain_file), "--pubkey", str(pub_path),
    ])
    with pytest.raises(SystemExit) as exc:
        run()
    assert exc.value.code == 1
    assert "is not a JSON object" in capsys.readouterr().err
