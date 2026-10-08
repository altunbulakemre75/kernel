# EU AI Act — what Kyvern's evidence supports

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

**What Kyvern records for Article 12(2):**

| Requirement | Kyvern mechanism | Report check |
|---|---|---|
| Art.12(2)(a) — Risk identification (Art.79(1)) | Each decision records `threat_level`, `roe_reference` and `guardrails_triggered` | `risk_fields` |
| Art.12(2)(b) — Post-market monitoring (Art.72) | Each decision records `policy_version_id` (SHA-256 of the policy file it was made under) | `policy_recorded` |
| Art.12(2)(c) — Operation monitoring (Art.26(5)) | Each decision records `action`, `timestamp_iso`, `requires_operator_approval` and `guardrail_reasoning` | `operation_fields` |
| Tamper-evident records (Art.12(1)) | Ed25519 signature + SHA-256 hash link per entry; `kyvern-verify` detects any change, and RFC 3161 anchors (`kyvern-anchor`) detect a rewrite even by the key holder | `integrity` |
| Timestamps | ISO 8601 in UTC | `timestamps` |
| Automatic recording | `run_graph()` appends each decision before returning it, and raises if it cannot. Whether every decision of a system goes through Kyvern depends on the integration, so the report cannot show it | `automatic` (NOT ASSESSED) |

**Retention.** Article 19(1) (providers) and Article 26(6) (deployers) require
automatically generated logs to be kept for a period appropriate to the
system's purpose, **of at least six months**, unless other Union or national
law says otherwise. (The ten-year period in Article 18 is for technical and
quality documentation, not logs.) Keeping the chain files is the provider's
and deployer's storage policy; Kyvern does not manage storage lifetime. The
report shows the earliest entry in the chain and its age (`retention`, INFO).

### Article 12(3) — Remote biometric identification (out of scope for Kyvern, included for reference)

Article 12(3) imposes *additional* logging requirements that apply
**only** to remote biometric identification systems listed in Annex III,
paragraph 1(a). Kyvern is a decision-provenance layer for autonomous
systems (robots, vehicles, effectors) — not a remote biometric
identification system. Article 12(3) is reproduced here for reference
only and is not part of Kyvern's compliance scope.

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

**What the chain can show for Article 14.** Human oversight is mostly a
property of the deployed system: who can see its output, stop it or override
it. The chain shows only what was recorded:

| Aspect | What Kyvern records | Report check |
|---|---|---|
| Approval before high-risk actions | Each decision records `requires_operator_approval`; ENGAGE decisions always set it. Enforcing the approval is the integration's job: Kyvern records that approval was required, not that it was given | `approval_flag` |
| Human interventions | Decisions an operator made, if the integration records them with `source=operator` | `operator_decisions` (INFO, or NOT ASSESSED if none) |
| Override or stop | Not visible in a chain | `override` (NOT ASSESSED) |
| Automated safety downgrades | `guardrails_triggered` and `guardrail_reasoning`; guardrails only lower an action (see the threat model). These are automated checks, not human oversight | `guardrails` (INFO) |
| Policy transparency | Policies are human-authored YAML; each decision records the SHA-256 of the policy it was made under, and `--policy` checks it | `policy` |

## What the report's results mean

Every row in the report's Article 12 and 14 tables is a check run on the
chain:

- **PASS / FAIL** — the check ran on the chain, with the counts as evidence.
- **NOT ASSESSED** — the chain cannot show it; the row says why.
- **N/A** — nothing to check (for example, no ENGAGE decisions).
- **INFO** — a figure, not a pass/fail claim.

If the chain fails integrity, the checks computed from its records are NOT
ASSESSED: unverified records are not evidence. A PASS supports an assessment
under the Article named; it does not establish conformity, which is assessed
under Article 43.

## When to use `kyvern-report`

| Scenario | Action |
|---|---|
| **Scheduled audit** | Run monthly, store PDFs alongside chain files |
| **Incident investigation** | Run against the chain segment covering the incident window using `--period` |
| **Regulator request** | Generate report from the requested chain, provide PDF + chain file + public key |
| **Pre-deployment review** | Run against a test chain to see which checks pass for the policy version you plan to deploy |

## Example

```bash
# Generate demo data
python scripts/generate_demo_chain.py

# Produce the evidence report
kyvern-report /tmp/kyvern-demo/chain.jsonl \
    --policy config/policies/default.yaml \
    --pubkey /tmp/kyvern-demo/signing.pub \
    --output evidence_report.pdf \
    --system-id "AMR-Fleet-A" \
    --operator "Operations Team" \
    --period "2026-05-16/2026-05-16"
```

## Disclaimer

This report establishes audit evidence based on observable, cryptographically
verifiable properties of the decision chain. It does not constitute third-party
certification (SOC 2, ISO 27001, or equivalent). Formal certification requires
an accredited conformity assessment body under Article 43 of the EU AI Act.
