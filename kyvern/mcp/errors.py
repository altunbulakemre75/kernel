class KyvernMCPError(Exception):
    """Raised for kyvern-mcp tool/resource handler errors.

    FastMCP surfaces the message in the JSON-RPC error response.
    """
