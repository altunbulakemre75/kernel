# MCP Server for kernel Audit Query — Design Spec

**Date:** 2026-05-18
**Status:** Draft, awaiting user approval
**Scope:** Read-only Model Context Protocol server exposing the kernel decision-audit chain to MCP clients (Claude Desktop is the canonical target).
**Out of scope (v1):** Write operations (covered by future `kernel-mcp-admin`, Phase 3), SSE transport, multi-chain federation, dashboarding.

---

## 1. Goal

A developer should be able to add `kernel` to their Claude Desktop in ~30 seconds and then ask, in natural language, *"what did my autonomous system do in the last hour?"* — receiving signed, verifiable audit evidence in the reply.

The server is the demo entry point for the wider `kernel` accountability story. It must therefore be:

1. **One command to install** — `pip install kernel[mcp]`.
2. **One config block to wire** — copy-paste JSON into Claude Desktop config.
3. **Read-only by construction** — no tool or resource mutates audit or policy state.
4. **Signature-honest** — every event returned exposes its signature verification status; chain breaks are never silently swallowed.

---

## 2. Threat & trust model

| Actor | Trusted with | Not trusted with |
|---|---|---|
| MCP client (Claude Desktop) | Reading audit events through the defined tool surface | Mutating chain, policy, or kernel state |
| kernel-mcp process | Local read access to `chain.jsonl` and `signing.pub` | Network egress (stdio-only in v1) |
| Audit chain on disk | Source of truth | — |

stdio-only transport means the server only talks to the local Claude Desktop instance launched it; there is no network listener. Signature verification gives the client cryptographic confidence that returned events were not tampered with after signing.

---

## 3. Architecture

```
Claude Desktop ──stdio──► kernel-mcp ──► AuditChainStore (JSONL reader, in-mem cache)
                              │
                              ├── tools:     query_events / get_event / get_stats / verify_chain / search_events
                              └── resources: kernel://audit/recent  kernel://stats/today
                                             kernel://chain/status   kernel://policy/active
```

- `AuditChainStore` is the only component that touches the filesystem chain. All tools and resources read through it.
- One source of truth: `~/.kernel/chain.jsonl` (CLI override available). No sidecar SQLite, no index file. v1 is deliberately a linear scan over an in-memory list.
- All Pydantic models for tool I/O live in `kernel/mcp/schemas.py`; the MCP SDK wraps them into the on-wire protocol.

---

## 4. File layout

| Path | Responsibility |
|---|---|
| `kernel/audit/__init__.py` | Package marker; re-exports `AuditChainStore`. |
| `kernel/audit/store.py` | `AuditChainStore` — JSONL loader, debounced mtime hot-reload, in-memory filter, signature & chain verification helpers. |
| `kernel/mcp/__init__.py` | SDK guard (`ImportError` with `pip install kernel[mcp]` hint when `mcp` missing) + public API re-exports. |
| `kernel/mcp/server.py` | CLI argparse, stdio server bootstrap, `run()` console entry. |
| `kernel/mcp/tools.py` | The 5 read-only tool handlers, wired to the MCP SDK tool decorator. |
| `kernel/mcp/resources.py` | The 4 resource handlers. |
| `kernel/mcp/schemas.py` | Pydantic input/output models for every tool. |
| `tests/audit/test_store.py` | Store unit tests (load, filter, verify helpers, hot-reload debouncing). |
| `tests/mcp/test_server.py` | Server startup + dispatcher tests. |
| `tests/mcp/test_tools.py` | One test per tool covering happy path + error contract. |
| `tests/mcp/test_resources.py` | All 4 resources return valid JSON, schema-stable. |
| `tests/mcp/test_integration.py` | Env-gated full MCP handshake (real `mcp` SDK client). |
| `examples/mcp_claude_desktop_config.json` | Copy-paste config block. |
| `docs/integrations/mcp.md` | 30-second setup, tool reference, threat model, roadmap. |

---

## 5. CLI surface

```
kernel-mcp [--chain-file PATH]
           [--pubkey PATH]
           [--policy PATH]
           [--verify-on-query / --no-verify-on-query]
```

| Flag | Default | Notes |
|---|---|---|
| `--chain-file` | `~/.kernel/chain.jsonl` | Path to the JSONL audit chain. |
| `--pubkey` | `~/.kernel/keys/signing.pub` | Matches the existing project convention at [`services/decision/audit_chain.py:14`](../../services/decision/audit_chain.py#L14). |
| `--policy` | `config/policies/default.yaml` | Used only by `kernel://policy/active`; never executed. |
| `--verify-on-query` | `true` | When `true`, every returned event includes a real `sig_valid` based on Ed25519 verification; when `false`, `sig_valid` is reported as `null` and the field documents that verification was disabled at startup. |

Console script wiring in `pyproject.toml`:

```toml
[project.scripts]
kernel-mcp = "kernel.mcp.server:run"
```

---

## 6. Dependencies

`mcp` is an **optional extra**, consistent with the existing `langgraph`/`anthropic` (`[llm]`) and `reportlab`/`pypdf` (`[compliance]`) patterns:

```toml
[project.optional-dependencies]
mcp = ["mcp>=1.0.0"]
```

`kernel/mcp/__init__.py` first executes:

```python
try:
    import mcp  # noqa: F401
except ImportError as e:
    raise ImportError(
        "kernel.mcp requires the 'mcp' extra.\n"
        "Install with: pip install kernel[mcp]"
    ) from e
```

So `from kernel.mcp import server` on a fresh install without the extra yields a single, actionable error.

---

## 7. `AuditChainStore` API

```python
class AuditChainStore:
    def __init__(
        self,
        chain_file: Path,
        public_key_path: Path | None = None,
        verify_on_query: bool = True,
        reload_debounce_seconds: float = 1.0,
    ) -> None: ...

    def load(self) -> None
    def reload_if_stale(self) -> None        # debounced — see §7.1
    def events(self) -> list[dict]
    def filter(
        self,
        *,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        action: str | None = None,
        threat_level: str | None = None,
        limit: int = 100,
    ) -> list[dict]
    def get(self, event_id: int) -> dict | None
    def search(self, query: str, limit: int = 50) -> list[SearchHit]   # see §7.2
    def verify_event(self, event_id: int) -> bool | None
    def verify_chain_range(self, start_id: int | None, end_id: int | None) -> ChainVerifyResult
```

### 7.1 Hot-reload debouncing

`reload_if_stale()` is called at the entry of every tool handler. To avoid `stat()` syscall overhead on high-frequency calls, the store keeps `_last_check_monotonic` and only re-stats `chain_file.mtime` when `monotonic() - _last_check_monotonic >= reload_debounce_seconds` (default 1.0s). Within a debounce window the cache is returned as-is.

This bounds worst-case staleness to 1 s of wall clock — acceptable for an auditor-facing demo and well below human read latency. The debounce window is configurable for tests.

### 7.2 `search` semantics

`query` is matched **case-insensitively, as a substring, against a recursively flattened string view of each event**. Concretely:

```python
def _flatten(obj) -> str:
    if isinstance(obj, dict): return " ".join(_flatten(v) for v in obj.values())
    if isinstance(obj, (list, tuple, set)): return " ".join(_flatten(v) for v in obj)
    return str(obj)
```

So a search for `"10.0.0.5"` matches an event with `{"target": {"ip": "10.0.0.5"}}`. Each `SearchHit` carries the event id, action, timestamp, and a 200-char snippet from the flattened representation centered on the match.

### 7.3 Verification helpers

`verify_event` and `verify_chain_range` wrap the existing primitives in [`services/decision/audit_chain.py`](../../services/decision/audit_chain.py) (`verify_decision`, `verify_chain`). The store does not reimplement crypto. If `public_key_path` is `None`, `verify_event` returns `None` (unknown) and `verify_chain_range` returns `ChainVerifyResult(integrity="UNKNOWN", reason="no public key configured")`.

---

## 8. MCP tool contracts

All inputs are validated by Pydantic; invalid inputs produce a structured `MCPError` (see §10). All event payloads in tool outputs **always include `sig_valid: bool | None`** — `null` only when `--verify-on-query=false` was set at startup.

### 8.1 `query_events`

Input:
```
start_time:    ISO-8601 | null
end_time:      ISO-8601 | null
action:        "allow" | "block" | "flag" | null
threat_level:  "low" | "medium" | "high" | null
limit:         int (1–1000, default 100)
```

Output: `list[EventSummary]` — id, timestamp, action, threat_level, sig_valid. Up to `limit` items, newest first.

### 8.2 `get_event`

Input: `event_id: int`.
Output: full event dict plus `sig_valid: bool | None` and `chain_link: "OK" | "BROKEN" | "UNKNOWN" | "GENESIS"` — verifies the link to `prev_hash` of the preceding event. `"GENESIS"` for `chain_index == 0` (no predecessor); `"UNKNOWN"` when `--no-verify-on-query`.

### 8.3 `get_stats`

Input: `window: "1h" | "24h" | "7d" | "30d" | "all"` (default `"24h"`).

Output:
```
action_distribution:   {allow: N, block: N, flag: N}
threat_distribution:   {low: N, medium: N, high: N}
chain_status:          {verified: N, total: N, integrity: "OK" | "BROKEN" | "UNKNOWN"}
period:                {start: ISO-8601, end: ISO-8601}
```

### 8.4 `verify_chain`

Input:
```
start_id: int | null (default 1)
end_id:   int | null (default latest)
```

Output:
```
verified_count: int
total_count:    int
first_break:    {id: int, reason: str} | null
integrity:      "OK" | "BROKEN" | "UNKNOWN"
```

### 8.5 `search_events`

Input: `query: str`, `limit: int` (default 50).
Output: `list[SearchHit]` (§7.2), each carrying id, timestamp, action, sig_valid, and a 200-char snippet.

---

## 9. MCP resources

| URI | Payload |
|---|---|
| `kernel://audit/recent` | JSON of the last 100 events (`EventSummary` shape). |
| `kernel://stats/today` | Same shape as `get_stats(window="24h")` but anchored to *server-host* local-day boundaries (`00:00–23:59:59` in the host's local timezone). Documented in the resource description so clients know not to expect a strict 24-hour rolling window. |
| `kernel://chain/status` | Result of `verify_chain_range(1, latest)` plus chain length and the chain file path. |
| `kernel://policy/active` | **Metadata only:** `{version_id, version_short, path, loaded_at}` from [`services/decision/policy_loader.LoadedPolicy`](../../services/decision/policy_loader.py). The `rules` body and `raw_bytes` are deliberately **not** exposed. Rationale: scope is read-only *audit* query; policy body inspection is out of scope and should remain a deliberate explicit action via the existing CLI tools. |

---

## 10. Error contract

| Condition | Behavior |
|---|---|
| Chain file missing | `MCPError("chain file not found at <path>")` at startup or first tool call. |
| Pubkey missing AND `--verify-on-query=true` | `MCPError("public key not found at <path> — pass --pubkey or use --no-verify-on-query")`. |
| Invalid ISO-8601 input | `MCPError("invalid time format — expected ISO 8601, e.g. 2026-05-18T14:32:07Z")`. |
| Out-of-range `limit` | `MCPError("limit must be between 1 and 1000")`. |
| Unknown `event_id` | Tool returns `null` (not an error — empty result, like SQL). |
| Signature verification fails for an event | Event is **still returned** with `sig_valid: false`; never silently dropped. |
| Chain break detected during `verify_chain` | `first_break: {id, reason}` populated; `integrity: "BROKEN"`. |
| Policy file missing for `kernel://policy/active` | Resource returns `{"error": "policy file not found at <path>"}` with HTTP-equivalent 200; not a fatal MCPError. |

---

## 11. Test plan

11 tests as specified (one renamed for accuracy):

1. `test_server_starts` — stdio server initializes without error against a tmp chain file.
2. `test_query_events_filters` — time, action, threat filters all work and compose.
3. `test_get_event_signature` — returns `sig_valid: true` on a clean event, `false` on a tampered one, `null` when verify-on-query disabled.
4. `test_get_stats_windows` — `1h`/`24h`/`7d`/`30d`/`all` partitions correctly.
5. `test_verify_chain_ok` — clean chain returns `integrity: OK`.
6. `test_verify_chain_broken` — tampered chain returns `first_break: {id, reason}`.
7. `test_search_events` — substring matching including a nested-field case (`{"target": {"ip": "10.0.0.5"}}` matches `"10.0.0.5"`).
8. `test_resources` — all 4 resources return valid JSON with the documented shapes.
9. `test_invalid_inputs` — bad ISO-8601, out-of-range limit, both raise `MCPError` with the documented message.
10. `test_chain_file_missing` — graceful, actionable error message (renamed from `test_db_missing`).
11. `test_integration_with_real_mcp_client` — env-gated by `KERNEL_MCP_E2E=1`, full handshake via the real `mcp` SDK client.

Plus `tests/audit/test_store.py`:

- Load + iterate + filter parity.
- `reload_if_stale` debounce (calls within 1 s do *not* re-stat; calls beyond do).
- `search` flatten over nested structures.
- Verify helpers return correct booleans on clean vs tampered fixtures.

---

## 12. Performance & roadmap

v1 is a linear scan over an in-memory `list[dict]`. Validated for the current demo profile (<10K events, single-host operation). The decision is documented in `docs/roadmap.md`:

> **Audit query indexing (>100K events).** kernel-mcp v1 runs in-memory linear scan over the JSONL chain. Adequate for <10K events. When deployments cross 100K events, revisit: (A.1) in-memory time-bucket cache for `query_events`/`get_stats`, (A.2) a SQLite index sidecar built from JSONL on chain reload. Defer until profiling justifies it — premature optimization until then.

`docs/integrations/mcp.md` also notes the SSE transport as a Phase 2 item and `kernel-mcp-admin` as Phase 3.

---

## 13. Definition of done

- [ ] `pip install kernel[mcp]` succeeds on a clean venv.
- [ ] `kernel-mcp --chain-file /tmp/kernel-demo/chain.jsonl` starts and responds to an MCP `initialize`.
- [ ] Demo flow in `docs/integrations/mcp.md` reproducible end-to-end: chain file in place → Claude Desktop config block → "what did my autonomous system do in the last hour" returns a signed event list.
- [ ] All 11 MCP tests + store tests pass; previous `pytest -k "not integration"` count grows by exactly the new tests, no regressions.
- [ ] Roadmap note added.
- [ ] `from kernel.mcp import server` on a venv without the extra raises the documented `ImportError` with install instruction.
