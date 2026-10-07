try:
    import mcp  # noqa: F401
except ImportError as exc:
    raise ImportError(
        "kyvern.mcp requires the 'mcp' extra.\n"
        "Install with (from the kyvern repo root): pip install -e \".[mcp]\""
    ) from exc

from kyvern.mcp.errors import KyvernMCPError

__all__ = ["KyvernMCPError"]
