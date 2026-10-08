# An honest EU AI Act evidence report

**Status:** approved by the maintainer (2026-10-08, "approve all")
**Scope:** `kyvern-report` (PDF), `docs/compliance/eu_ai_act.md`, the README and
docs/index.md sections that describe the report.

## 1. Problem

The report's Article 12 and 14 tables print "✓ PASS" for eight rows whatever the
chain contains. Some of them claim things a chain cannot show ("operator
override capability", "automatic log generation"); one presents automated
guardrail downgrades as "human interventions". The retention row says ten
years: that is the period for technical documentation (Art. 18); logs must be
kept for at least six months (Art. 19(1) for providers, Art. 26(6) for
deployers). `docs/compliance/eu_ai_act.md` says "How Kyvern satisfies Article
12/14" and that operator-approval decisions "block escalation until a human
authorises", which Kyvern does not do: it records the flag.

## 2. Principles

1. Every row is a check run on this chain, with the result and the evidence.
2. Results: **PASS / FAIL** (the check ran), **NOT ASSESSED** (the chain cannot
   show it, with the reason), **N/A** (nothing to check), **INFO** (a figure,
   not a pass/fail claim).
3. A row names the Article it *supports*. A PASS is evidence for an assessment;
   it does not establish conformity (Art. 43). The report says so.
4. If the chain fails integrity, rows computed from its records are NOT ASSESSED:
   unverified records are not evidence (same rule as the policy check in 0.3.2).

## 3. Rows

Article 12 (record-keeping):

| id | Check | Supports | Result |
|---|---|---|---|
| `integrity` | Every entry signed and hash-linked | Art. 12(1) | PASS/FAIL |
| `risk_fields` | Each decision records threat level, rule reference, guardrails | Art. 12(2)(a) | PASS/FAIL (k of n) |
| `policy_recorded` | Each decision records the policy version it was made under | Art. 12(2)(b) | PASS/FAIL (k of n) |
| `operation_fields` | Each decision records action, timestamp, approval flag, guardrail reasoning | Art. 12(2)(c) | PASS/FAIL (k of n) |
| `timestamps` | Every entry's timestamp is ISO 8601 in UTC | Art. 12(1) | PASS/FAIL |
| `automatic` | Records generated automatically | Art. 12(1) | NOT ASSESSED |
| `retention` | Logs kept at least six months | Art. 19(1), 26(6) | INFO (earliest entry, age) |

Article 14 (human oversight):

| id | Check | Result |
|---|---|---|
| `approval_flag` | ENGAGE decisions flagged as requiring operator approval | PASS/FAIL, N/A without ENGAGE |
| `operator_decisions` | Decisions recorded with `source=operator` | INFO (count) or NOT ASSESSED (none) |
| `override` | Operator can override or stop the system | NOT ASSESSED |
| `guardrails` | Automated guardrail downgrades recorded | INFO (count; labelled automated) |
| `policy` | Decisions bound to a supplied policy | PASS/FAIL (existing check) |

With no decisions, the per-decision rows are N/A.

## 4. Other changes

- The report fingerprint also covers each row's result.
- Wording: "evidence that supports", not "compliance"/"satisfies"; the cover and
  the Article 12 page state what PASS means and that conformity assessment is
  outside the report.
- `docs/compliance/eu_ai_act.md` lists the checks, fixes retention, and stops
  claiming that Kyvern blocks escalation or provides override.

## 5. Tests

A pure `compute_checks()` is unit-tested: each row changes with the chain
(missing fields, ENGAGE without the flag, operator decisions, non-UTC
timestamps, broken chain, empty chain). PDF tests check the wording (no
"satisfies", no "10 years", "six months", "does not establish").

## 6. Out of scope

Signing the report itself, Article 13/15/72 content, and records from the
decision-recording API (next piece; it reuses these checks).
