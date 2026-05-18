"""kernel-mcp — stdio MCP server entry point."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from kernel.audit import AuditChainStore
from kernel.mcp.errors import KernelMCPError
from kernel.mcp.resources import register_resources
from kernel.mcp.tools import register_tools


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="kernel-mcp",
        description="kernel — read-only MCP server for audit chain query.",
    )
    parser.add_argument(
        "--chain-file",
        dest="chain_file",
        default=os.path.expanduser("~/.kernel/chain.jsonl"),
    )
    parser.add_argument(
        "--pubkey",
        dest="pubkey",
        default=os.path.expanduser("~/.kernel/keys/signing.pub"),
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
    return parser.parse_args(argv)


def build_app(
    *,
    chain_file: Path | str,
    pubkey: Path | str | None,
    policy: Path | str | None,
    verify_on_query: bool,
) -> FastMCP:
    chain_file = Path(chain_file)
    if not chain_file.exists():
        raise KernelMCPError(f"chain file not found at {chain_file}")

    pubkey_path = Path(pubkey) if pubkey else None
    if verify_on_query:
        if pubkey_path is None or not pubkey_path.exists():
            raise KernelMCPError(
                f"public key not found at {pubkey_path} — "
                "pass --pubkey or use --no-verify-on-query"
            )

    store = AuditChainStore(
        chain_file=chain_file,
        public_key_path=pubkey_path if verify_on_query else None,
        verify_on_query=verify_on_query,
    )
    store.load()

    policy_path = Path(policy) if policy else None

    app = FastMCP("kernel")
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
