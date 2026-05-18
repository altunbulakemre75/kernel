# EU AI Act Compliance — kernel Mapping

> Source: Regulation (EU) 2024/1689, Official Journal of the European Union, 12 July 2024

## Article 12 — Record-keeping

### Article 12(2) — General logging requirements for high-risk AI systems

Article 12(2) requires that high-risk AI systems automatically generate
logs sufficient to enable three specific accountability purposes:

- **(a)** ensuring the system can be used for the purpose of identifying
  risks at national level under Article 79(1)
- **(b)** ensuring post-market monitoring under Article 72
- **(c)** ensuring the monitoring under Article 26(5) (deployer
  operational obligations)

**How kernel satisfies Article 12(2):**

| Requirement | kernel mechanism |
|---|---|
| Art.12(2)(a) — Risk identification logging (Art.79(1)) | Each decision records `threat_level`, `roe_reference`, and full `guardrails_triggered` trace; the signed chain is the national-level risk evidence record |
| Art.12(2)(b) — Post-market monitoring support (Art.72) | All decisions are auto-logged with `policy_version_id` (SHA-256 of the policy file), enabling retrospective analysis against any deployed rule version |
| Art.12(2)(c) — Operation monitoring (Art.26(5)) | `action`, `timestamp_iso`, `roe_reference`, `requires_operator_approval`, and `guardrail_reasoning` are recorded per decision; deployers can replay the full operational picture |
| Automatic log generation | Every call to `sign_decision()` appends a tamper-evident record to the audit chain without human action |
| Tamper-evident storage | Ed25519 signature + SHA-256 hash chain — any modification breaks the chain and is detected by `kernel-verify` |
| Standardised timestamps | All timestamps are ISO 8601 UTC |

Retention of the chain files (10-year requirement for high-risk systems)
is the responsibility of the deployment operator. kernel does not manage
storage lifetime.

### Article 12(3) — Remote biometric identification (out of scope for kernel, included for reference)

Article 12(3) imposes *additional* logging requirements that apply
**only** to remote biometric identification systems listed in Annex III,
paragraph 1(a). kernel is a decision-provenance layer for autonomous
systems (robots, vehicles, effectors) — not a remote biometric
identification system. Article 12(3) is reproduced here for reference
only and is not part of kernel's compliance scope.

The Article 12(3) requirements (biometric ID systems only) are:

- the period of use of the system
- the reference database against which input data has been checked
- the input data that led to a given output, where practicable
- the identity of the natural persons involved in the verification

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
