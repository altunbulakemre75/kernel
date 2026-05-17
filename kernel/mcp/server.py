"""kernel-mcp stdio server (stub).

The real implementation lands in Task 8 of
docs/superpowers/plans/2026-05-18-mcp-audit-server.md.
This stub exists so the kernel-mcp console-script entry point is importable
during intermediate commits in subagent-driven development.
"""
from __future__ import annotations


def run() -> None:
    raise NotImplementedError(
        "kernel-mcp server is not yet wired up (Task 8 of the plan). "
        "Install the full implementation before invoking this script."
    )
