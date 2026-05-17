class KernelMCPError(Exception):
    """Raised for kernel-mcp tool/resource handler errors.

    FastMCP surfaces the message in the JSON-RPC error response.
    """
