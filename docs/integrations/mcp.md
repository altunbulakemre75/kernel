# kernel-mcp — Read-Only Audit Query Server (MCP)

`kernel-mcp` is a Model Context Protocol server that exposes the kernel
decision-audit chain to Claude Desktop (and any MCP-compatible client) over
stdio. Read-only by construction — no tool mutates audit or policy state.

## 30-Second Setup (Claude Desktop)

1. **Install the extra:**

   ```bash
   pip install kernel[mcp]
   ```

2. **Generate or point at a signed chain.** If you don't have one yet:

   ```bash
   python scripts/generate_demo_chain.py
   # → /tmp/kernel-demo/chain.jsonl + signing.pub
   ```

3. **Edit your Claude Desktop config** (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS;
   `%APPDATA%\Claude\claude_desktop_config.json` on Windows) and add:

   ```json
   {
     "mcpServers": {
       "kernel": {
         "command": "kernel-mcp",
         "args": [
           "--chain-file", "/tmp/kernel-demo/chain.jsonl",
           "--pubkey", "/tmp/kernel-demo/signing.pub"
         ]
       }
     }
   }
   ```

4. **Restart Claude Desktop.** You can now ask: *"what did my autonomous system do in the last hour?"*

## Tools

| Name | Purpose |
|---|---|
| `query_events` | Filter audit events by time / action / threat level. Returns id, timestamp, action, threat_level, sig_valid. |
| `get_event` | Full event by `chain_index` + signature + chain-link status. |
| `get_stats` | Aggregated stats for `1h`/`24h`/`7d`/`30d`/`all` windows. |
| `verify_chain` | Verify a range; returns `first_break` and `integrity`. |
| `search_events` | Case-insensitive substring search over the recursively flattened event content. |

Example invocation (via Claude Desktop):

> "Use `query_events` to fetch high-threat events from the last 24 hours."

## Resources

| URI | Payload |
|---|---|
| `kernel://audit/recent` | Last 100 events. |
| `kernel://stats/today` | Stats anchored to today's local-day boundaries on the server host. |
| `kernel://chain/status` | Integrity result + chain length. |
| `kernel://policy/active` | Metadata only — `version_id`, `version_short`, `path`, `loaded_at`. Body is not exposed. |

## Threat Model

- stdio-only transport in v1 — no network listener.
- All event payloads carry `sig_valid` (`true`/`false`/`null`). Verification failures are never silently dropped.
- The server reads from a single chain file; it never writes.
- Policy resource exposes metadata only, not the rule body.

## Roadmap

- **v1 (this release):** stdio transport, 5 read-only tools, 4 resources.
- **Phase 2:** SSE transport for remote MCP clients.
- **Phase 3:** `kernel-mcp-admin` for write operations (rotate keys, archive chain segments) — separate binary, separate auth model.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `chain file not found at <path>` | Wrong `--chain-file` path, or chain not generated yet. |
| `public key not found ...` | Pubkey path missing; pass `--pubkey` or `--no-verify-on-query`. |
| `ImportError: kernel.mcp requires the 'mcp' extra` | Run `pip install kernel[mcp]`. |
