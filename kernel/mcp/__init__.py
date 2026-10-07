try:
    import mcp  # noqa: F401
except ImportError as exc:
    raise ImportError(
        "kernel.mcp requires the 'mcp' extra.\n"
        "Install with (from the kernel repo root): pip install -e \".[mcp]\""
    ) from exc

from kernel.mcp.errors import KernelMCPError

__all__ = ["KernelMCPError"]
