"""kyvern-mcp — stdio MCP server entry point."""
from __future__ import annotations

import argparse
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from kyvern.audit import AuditChainStore
from kyvern.mcp.errors import KyvernMCPError
from kyvern.mcp.resources import register_resources
from kyvern.mcp.tools import register_tools
from shared.paths import default_chain_path, kyvern_home


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="kyvern-mcp",
        description="Kyvern — read-only MCP server for audit chain query.",
    )
    parser.add_argument(
        "--chain-file",
        dest="chain_file",
        default=str(default_chain_path()),
    )
    parser.add_argument(
        "--pubkey",
        dest="pubkey",
        action="append",
        default=None,
        help="Ed25519 public key PEM; repeat for chains signed by several keys",
    )
    parser.add_argument(
        "--policy",
        dest="policy",
        default="config/policies/default.yaml",
    )
    parser.add_argument(
        "--verify-on-query",
        dest="verify_on_query",
        action="store_true",
        default=True,
    )
    parser.add_argument(
        "--no-verify-on-query",
        dest="verify_on_query",
        action="store_false",
    )
    ns = parser.parse_args(argv)
    if ns.pubkey is None:
        ns.pubkey = [str(kyvern_home() / "keys" / "signing.pub")]
    return ns


def build_app(
    *,
    chain_file: Path | str,
    pubkey: Path | str | list[Path | str] | None,
    policy: Path | str | None,
    verify_on_query: bool,
) -> FastMCP:
    chain_file = Path(chain_file)
    if not chain_file.exists():
        raise KyvernMCPError(f"chain file not found at {chain_file}")

    raw_paths = pubkey if isinstance(pubkey, (list, tuple)) else [pubkey]
    pubkey_paths = [Path(p) for p in raw_paths if p]
    if verify_on_query:
        missing = [p for p in pubkey_paths if not p.exists()]
        if not pubkey_paths or missing:
            raise KyvernMCPError(
                f"public key not found at {missing[0] if missing else None} — "
                "pass --pubkey or use --no-verify-on-query"
            )

    store = AuditChainStore(
        chain_file=chain_file,
        public_key_paths=pubkey_paths if verify_on_query else None,
        verify_on_query=verify_on_query,
    )
    store.load()

    policy_path = Path(policy) if policy else None

    app = FastMCP("kyvern")
    register_tools(app, store, policy_path=policy_path)
    register_resources(app, store, policy_path=policy_path)
    return app


def run() -> None:
    ns = parse_args()
    app = build_app(
        chain_file=ns.chain_file,
        pubkey=ns.pubkey,
        policy=ns.policy,
        verify_on_query=ns.verify_on_query,
    )
    app.run(transport="stdio")


if __name__ == "__main__":
    run()
