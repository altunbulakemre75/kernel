# v0.3.2 — Auditor tools agree with the pipeline

**Status:** approved for implementation (2026-10-08)
**Scope:** `kyvern-verify`, `kyvern-report`, the MCP `verify_chain` tool, and the
shared verification helpers they use. No change to the chain format or to how
entries are signed.

## 1. Problem

The v0.3.x pipeline writes one chain holding Decisions and RuntimeEvents. The
tools an auditor uses to read that chain were written for decision-only,
policy-bound chains, and disagree with what the pipeline actually produces.
Each case below was reproduced on `main` (254534c):

| # | Input | Tool | What happens |
|---|---|---|---|
| 1 | `run_graph()` / `decide_full()` without `policy_path` (`policy_version_id` is `null`) | `kyvern-report` | Crashes with `TypeError` in the policy timeline; no PDF |
| 2 | same chain | `kyvern-verify` | `Policy match: FAILED — Decision does not contain a policy_version_id`, stops at the first entry, gives no count and no hint |
| 3 | chain with RuntimeEvents | `kyvern-verify`, `kyvern-report` | Each event is counted as a decision with `action=UNKNOWN`; the PDF shows `UNKNOWN` in the action distribution |
| 4 | RuntimeEvent appended as in the README (`policy_version_id="p_v1"`) | `kyvern-verify` | Fails the policy check, although the event's policy id is informational |
| 5 | chain that spans a policy update | `kyvern-verify`, `kyvern-report` | `--policy` takes one file, so the chain can never pass |
| 6 | any chain, wrong `--policy` | `kyvern-report` | The policy is never compared with the chain; the PDF says "Verifiable policy deployment ✓ PASS" and exits 0 |
| 7 | MCP `verify_chain(start_id>0)` on a valid chain | `kyvern-mcp` | Reports `BROKEN: broken prev_hash link` at the first entry of the range |

No test runs the pipeline's own output through the auditor tools, which is why
all seven passed CI.

## 2. Decisions

1. **The policy check covers Decisions only.** A Decision's `policy_version_id`
   is the claim "these rules produced this action", so it must match a policy
   the auditor supplies. A RuntimeEvent's `policy_version_id` only records which
   policy was in force when the event was appended; tools show it but do not
   check it. `append_runtime_event(..., policy_version_id=None)` becomes the
   default.
2. **Unbound Decisions fail the policy check, with a clear reason.** A Decision
   with no `policy_version_id` cannot be tied to any rule set, so an auditor
   cannot verify it against one. `kyvern-verify` and `kyvern-report` report how
   many Decisions are unbound and at which chain positions, say that they were
   recorded without `policy_path`, and exit 1. The pipeline keeps accepting
   calls without `policy_path` (no API break); the README and docstrings say
   that such decisions will not pass a policy check.
3. **`--policy` is repeatable** in both CLIs. Every Decision must be bound to one
   of the given policies. Output lists how many Decisions each policy covers,
   and names any `policy_version_id` that matches none of them.
4. **Record types are counted separately.** Integrity lines, summaries, PDF
   counts and distributions use Decisions for action/threat figures and list
   RuntimeEvents by `event_type` and `source`. A record without `record_type`
   is a Decision (chains written before RuntimeEvent existed).
5. **`kyvern-report` computes the policy row.** "Verifiable policy deployment" is
   PASS only when the policy check passes; otherwise FAIL with the reason. The
   report is still written, and the exit code is 1 when the chain or the policy
   check fails (as for a broken chain today). The other hard-coded Article 12/14
   rows are out of scope here (next release: "honest compliance report").
6. **Subrange verification seeds the hash link.** `verify_chain()` and
   `describe_chain_failure()` take an optional `prev_hash` for the first entry
   (default `None`, i.e. the slice starts at genesis). The MCP store passes the
   payload hash of the entry just before the range. Verifying a range therefore
   trusts the link into it; the tool description says so.

## 3. Shared helper

`services/decision/audit_chain.py` gains:

- `record_type_of(record) -> str` — `"runtime_event"` or `"decision"`.
- `check_policy_binding(records, policies, broken_at=None) -> PolicyCheck` —
  `policies` is a list of `LoadedPolicy`; `broken_at` is the index
  `verify_chain()` returned for the same records. `PolicyCheck` holds `ok`,
  `per_policy` (version id → number of Decisions), `unbound` (chain positions of
  Decisions without a policy id) and `unknown` (position → policy id not among
  `policies`), plus `reason()` for a one-line explanation. The check also fails
  when the chain holds no Decision or `broken_at` is set (added after review).

`verify_decision_against_policy()` stays for API compatibility.

## 4. Tests

One end-to-end module, `tests/test_auditor_tools.py`, runs real pipeline output
through all three tools:

- bound pipeline Decisions + a RuntimeEvent → `kyvern-verify` exit 0 with
  separate counts and no `UNKNOWN`; `kyvern-report` exit 0, PDF counts match;
  MCP store `verify_chain_range(start>0)` is `OK`
- unbound pipeline Decisions → `kyvern-verify` exit 1 naming the unbound count;
  `kyvern-report` writes a PDF (no crash), exit 1, policy row FAIL
- a policy update mid-chain → passes with both `--policy`, fails with one and
  names the unknown version
- `kyvern-report` with a policy that does not match → exit 1, policy row FAIL

Unit tests cover `check_policy_binding()` and `verify_chain(prev_hash=...)`.

## 5. Out of scope

- Computing the remaining Article 12/14 rows, the retention wording and the
  report-signing option (next release).
- Tail truncation detection and `--require-anchors`.
- Making `policy_path` mandatory in `run_graph()`.
