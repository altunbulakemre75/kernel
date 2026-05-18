# kernel Threat Model

> Last updated: 2026-05-19 · Status: pre-1.0

## Scope

kernel is accountability infrastructure for autonomous systems. It provides
cryptographically signed, append-only decision audit chains and AI advisory
fail-safes. This document defines what kernel does — and does not — defend
against.

Knowing what a system does *not* defend against is at least as important as
knowing what it does. Overclaiming is the failure mode; this document is
written to avoid it.

---

## Primary Threats kernel Defends Against

### Threat 1: Insider/operator post-hoc tampering of decision history

**Scenario.** After an incident, an operator, employee, or other insider
attempts to alter, delete, or fabricate decision log entries to mislead
investigators, regulators, or courts. The motive is plausible deniability or
liability avoidance.

**Defense.** Every decision is Ed25519-signed and SHA-256 chain-linked to its
predecessor. The signing and linking happen at write time inside
`sign_decision()` in `services/decision/audit_chain.py`. Any subsequent
mutation — of payload, action, timestamp, or any other field — breaks chain
verification. The break is detectable at `kernel-verify` time:

```bash
kernel-verify chain.jsonl --policy config/policies/default.yaml \
    --pubkey signing.pub
# → ✗ Chain broken at index 3 (if tampered)
```

The tamper is detectable; the original state is unrecoverable to the attacker
without the signing private key.

**Result.** The attack surface shifts from the log file — low-protection,
on-disk — to key management, which is HSM/KMS territory and a much harder
problem for an insider. An attacker who cannot forge signatures cannot silently
rewrite history. See [`docs/architecture.md §4`](architecture.md) for the
full audit chain design.

---

### Threat 2: AI-induced unsafe escalation

**Scenario.** An LLM advisor — potentially manipulated via prompt injection,
adversarial input, or simply faulty reasoning — recommends a dangerous action
that the rule engine alone would not produce. The system acts on the
recommendation.

**Defense.** Three independent layers prevent this:

**(a) LLM advisory ceiling.** The LLM advisor is structurally prohibited from
recommending ENGAGE — the highest-severity action. Its maximum proposal is
HANDOFF. This is enforced in `llm_advisor.py` (`_reconcile_action`): the
advisor can escalate LOG → ALERT → HANDOFF but nothing beyond. An LLM that
returns ENGAGE is treated as a protocol violation, not a valid input.

**(b) Guardrail downgrade-only invariant.** Guardrails run *after* LLM
reconciliation and can only reduce severity, never increase it. The
`_SEVERITY` ordering in `guardrails.py` enforces this mathematically: a
guardrail that returns `downgrade_to=ENGAGE` when the current action is ALERT
is silently discarded. The worst-case outcome of a guardrail bug is an
unnecessary downgrade to LOG — the safest possible state. See
[`docs/architecture.md §6`](architecture.md) for the full downgrade-only
invariant.

**(c) Prompt injection quarantine.** Track data never reaches the LLM prompt
unfiltered. `sanitize.py` (`sanitize_track_for_llm`) applies allowlist
filtering, control-character stripping, and injection-pattern detection before
any track field enters the prompt. This limits the blast radius of adversarial
sensor inputs.

**Result.** AI is structurally an advisor; the rule engine is the decider. A
compromised, manipulated, or simply wrong LLM cannot cause the system to take
an action more aggressive than the rule engine would have taken without it.

---

## Threats kernel Explicitly Does NOT Defend Against

These are deployment-operator responsibilities. We list them to avoid
overclaiming in due diligence, interviews, or compliance assessments.

### Signing key compromise

If an attacker obtains the signing private key, they can produce arbitrary
"valid" chains that pass `kernel-verify`. kernel does not perform key
management. Operators must use an HSM, KMS, or equivalent hardware-backed key
store, with the private key never materialized on the host running kernel.

### Wholesale chain replacement

If an attacker replaces the entire chain file with one signed by a key they
control, and the public-key trust anchor itself is compromised or unverified,
`kernel-verify` will report the replacement chain as valid. Trust anchor
verification — how a verifier obtains and trusts the public key — is the
operator's responsibility. kernel provides the verification mechanism; it
cannot solve the key-distribution problem.

### Sensor-level truth

kernel trusts its inputs. If a sensor lies, or upstream data is poisoned
before reaching `FusionService`, the resulting decision will be logged
faithfully — including the full provenance of why that decision was made.
The logged record is cryptographically correct; the underlying premises are
not. Sensor integrity, calibration auditing, and input-source authentication
are out of scope.

### Runtime intrusion and process isolation

Container escapes, privilege escalation, or direct compromise of the host
process running kernel are not kernel's responsibility. Standard host
hardening, OS-level security, and container isolation policies apply. If the
process itself is compromised, the signing key in memory is compromised too.

### Network-level attacks

The MCP server (`kernel-mcp`) is stdio-only in v1 — there is no network
listener and therefore no network attack surface. This is a deliberate design
choice that limits exposure, not an active network defense mechanism. Future
SSE/HTTP transport (Phase 2) will require TLS, authentication, and
rate-limiting; those are deployment concerns, not kernel guarantees. See
[`docs/integrations/mcp.md`](integrations/mcp.md) for the MCP threat model
note.

---

## Honest One-Line Summary

kernel defends against insider post-hoc tampering of decision history and
AI-induced unsafe escalation. It does not defend against signing key
compromise, sensor-level deception, runtime intrusion, or network attacks —
those are operator responsibilities.

---

## What This Means for Compliance Claims

kernel produces tamper-evident decision audit trails suitable for the
Article 12(2) general logging requirements under Regulation (EU) 2024/1689
(risk identification per Art.79(1), post-market monitoring per Art.72,
operation monitoring per Art.26(5)). See
[`docs/compliance/eu_ai_act.md`](compliance/eu_ai_act.md).

kernel is **not** a substitute for:

- Key management policy (HSM, KMS, key rotation procedures)
- Sensor calibration auditing or input-source authentication
- Host hardening and container isolation
- Network security (TLS, authentication, rate-limiting)
- Third-party conformity assessment under Article 43 of the EU AI Act
