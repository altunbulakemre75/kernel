"""End-to-end MCP client/server handshake — env-gated by KERNEL_MCP_E2E=1."""
import asyncio
import os
import sys

import pytest


@pytest.mark.integration
def test_integration_with_real_mcp_client(sample_chain_file, signing_keypair, tmp_path):
    if not os.environ.get("KERNEL_MCP_E2E"):
        pytest.skip("Set KERNEL_MCP_E2E=1 to run integration tests")

    _, _, pub_path = signing_keypair

    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m", "kernel.mcp.server",
            "--chain-file", str(sample_chain_file),
            "--pubkey", str(pub_path),
            "--no-verify-on-query",
        ],
    )

    async def _run() -> dict:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                tool_names = {t.name for t in tools.tools}
                result = await session.call_tool("query_events", {"limit": 10})
                return {"tool_names": tool_names, "first_event": result.content[0]}

    out = asyncio.run(_run())
    expected_tools = {"query_events", "get_event", "get_stats", "verify_chain", "search_events"}
    assert expected_tools.issubset(out["tool_names"])
