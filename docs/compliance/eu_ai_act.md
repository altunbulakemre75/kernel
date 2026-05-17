# EU AI Act Compliance — kernel Mapping

## Article 12 — Automatic Logging

Article 12 of the EU AI Act requires that high-risk AI systems
automatically generate logs sufficient to enable ex-post accountability.
Specifically, systems must record:

- the period of operation of the system
- the reference database against which input data has been checked
- input data that led to a given output, where practicable
- the identity of the persons involved in verification

**How kernel satisfies Article 12:**

| Requirement | kernel mechanism |
|---|---|
| Automatic log generation | Every call to `sign_decision()` appends a tamper-evident record to the audit chain without human action |
| Event traceability | Each decision stores `roe_reference` (rule that fired), `timestamp_iso`, `threat_level`, `action`, and `guardrails_triggered` |
| Standardised timestamps | All timestamps are ISO 8601 UTC |
| Tamper-evident storage | Ed25519 signature + SHA-256 hash chain — any modification breaks the chain and is detected by `kernel-verify` |
| Policy traceability | `policy_version_id` (SHA-256 of policy file) is embedded in every decision, so the exact rule set is reconstructable |

Retention of the chain files (10-year requirement for high-risk systems)
is the responsibility of the deployment operator. kernel does not manage
storage lifetime.

## Article 14 — Human Oversight

Article 14 requires that high-risk AI systems be designed to allow natural
persons to effectively oversee operation, including the ability to:

- understand the system's capabilities and limitations
- monitor operation and detect anomalies
- override or interrupt the system
- take informed decisions based on system output

**How kernel satisfies Article 14:**

| Requirement | kernel mechanism |
|---|---|
| Human approval gate | Decisions with `requires_operator_approval: true` block escalation until a human authorises |
| Override capability | Guardrail-downgrade-only pattern ensures the system can only make decisions safer; operator can always intervene |
| Audit trail of interventions | `guardrails_triggered` and `guardrail_reasoning` are signed into every decision |
| Policy transparency | Policies are human-authored YAML; every deployed version is SHA-256 identified |

## When to use `kernel-report`

| Scenario | Action |
|---|---|
| **Scheduled audit** | Run monthly, store PDFs alongside chain files |
| **Incident investigation** | Run against the chain segment covering the incident window using `--period` |
| **Regulator request** | Generate report from the requested chain, provide PDF + chain file + public key |
| **Pre-deployment review** | Run against a test chain to confirm the policy version produces expected compliance evidence |

## Example

```bash
# Generate demo data
python scripts/generate_demo_chain.py

# Produce compliance report
kernel-report /tmp/kernel-demo/chain.jsonl \
    --policy config/policies/default.yaml \
    --pubkey /tmp/kernel-demo/signing.pub \
    --output compliance_report.pdf \
    --system-id "AMR-Fleet-A" \
    --operator "Operations Team" \
    --period "2026-05-16/2026-05-16"
```

## Disclaimer

This report establishes audit evidence based on observable, cryptographically
verifiable properties of the decision chain. It does not constitute third-party
certification (SOC 2, ISO 27001, or equivalent). Formal certification requires
an accredited conformity assessment body under Article 43 of the EU AI Act.
