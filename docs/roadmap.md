# Kyvern — Roadmap

## Audit query indexing (>100K events)

`kyvern-mcp` v1 runs an in-memory linear scan over the JSONL audit chain.
Adequate for the current demo profile (<10K events). When deployments
cross 100K events, revisit:

- **A.1** — in-memory time-bucket cache for `query_events` and `get_stats`.
- **A.2** — SQLite index sidecar built from JSONL on chain reload; treats
  JSONL as the source of truth, SQLite as a derived read-cache.

Defer until profiling justifies it. Premature optimisation until then.

## kyvern-mcp Phase 2 — SSE transport

Stdio-only in v1; SSE will enable remote MCP clients. Requires
authentication design (likely Ed25519 signed bearer tokens against
the same key material that signs the audit chain).

## kyvern-mcp Phase 3 — `kyvern-mcp-admin`

Separate binary for write operations: key rotation, chain segment
archival, policy upload. Distinct auth model. Out of scope for v1.
