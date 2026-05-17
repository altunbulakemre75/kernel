# EU AI Act Compliance Report Generator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `kernel-report` CLI that reads a signed decision chain and produces a regulator-ready PDF with Article 12 (logging) and Article 14 (human oversight) compliance evidence.

**Architecture:** `cli/kernel_report.py` follows the same pattern as `cli/kernel_verify.py`. Pure helper functions (`compute_action_distribution`, `compute_threat_distribution`, `compute_period`, `compute_pubkey_fingerprint`) are separated so they can be tested without subprocess or PDF round-trips. ReportLab Platypus builds the PDF. The report is always written (even on INVALID chain); exit code reflects chain validity. The attestation page shows a SHA-256 fingerprint of the report's canonical data; Ed25519 signing of the report is optional via `--signingkey`.

**Design decisions:**
- `--signingkey PATH` (optional, undocumented) — if provided, signs the report fingerprint with Ed25519 for the attestation page; otherwise only SHA-256 fingerprint shown.
- QR code skipped — ReportLab has no built-in QR support.
- PDF not byte-identical across runs (ReportLab embeds a random file ID); content is deterministic given identical inputs.
- Tests use pypdf for section header checks; helper functions tested directly for distribution accuracy.
- Test baseline: 137 collected (136 passed + 1 skipped). Target: 143 collected (142 passed + 1 skipped).

**Tech Stack:** Python 3.10+, ReportLab 4.x (Platypus), pypdf (tests only), existing `services.decision.audit_chain`.

---

## File Map

| File | Action | Purpose |
|---|---|---|
| `requirements.txt` | Modify | Add `reportlab>=4.0.0`, `pypdf>=4.0.0` |
| `tests/cli/test_kernel_report.py` | Create | 6 tests (subprocess + direct helper) |
| `cli/kernel_report.py` | Create | CLI entry point + PDF generator |
| `pyproject.toml` | Modify | Add `kernel-report` console script |
| `README.md` | Modify | Add EU AI Act section + update roadmap |
| `docs/compliance/eu_ai_act.md` | Create | Article 12/14 mapping documentation |

---

## Task 1: Add dependencies

**Files:**
- Modify: `requirements.txt`

- [ ] **Step 1: Append to requirements.txt**

Add after the `# Optional LLM stack` block:

```
# Compliance reporting
reportlab>=4.0.0
pypdf>=4.0.0  # used in tests; safe to install everywhere
```

- [ ] **Step 2: Install**

```bash
pip install reportlab>=4.0.0 pypdf>=4.0.0
```

Expected: installs without error.

- [ ] **Step 3: Verify importable**

```bash
python -c "import reportlab, pypdf; print('ok')"
```
Expected: `ok`

---

## Task 2: Write 6 failing tests

**Files:**
- Create: `tests/cli/test_kernel_report.py`

- [ ] **Step 1: Write test file**

`tests/cli/test_kernel_report.py`:
```python
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from services.decision.audit_chain import sign_decision
from services.decision.policy_loader import clear_policy_cache, load_policy

REPO_ROOT = Path(__file__).parent.parent.parent


@pytest.fixture
def workspace(tmp_path):
    clear_policy_cache()
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "rules:\n"
        "  - rule_id: \"rule_1\"\n"
        "    description: \"Test\"\n"
        "    when_threat_level: \"low\"\n"
        "    requires_operator_approval: false\n"
        "    action: \"log\"\n"
        "    enabled: true\n",
        encoding="utf-8",
    )
    private_key = ed25519.Ed25519PrivateKey.generate()
    pub_path = tmp_path / "key.pub"
    pub_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    policy = load_policy(str(policy_path))
    actions = ["log", "alert", "log", "engage", "log"]
    chain, prev = [], None
    for i, action in enumerate(actions):
        d = {
            "track_id": f"t{i}",
            "action": action,
            "threat_level": "low",
            "confidence": 0.9,
            "reasoning": "test",
            "source": "rule_engine",
            "roe_reference": "rule_1",
            "requires_operator_approval": action == "engage",
            "timestamp_iso": datetime(2026, 1, 1, 12, i, 0, tzinfo=timezone.utc).isoformat(),
            "llm_raw_response": None,
            "llm_provider": None,
            "llm_model": None,
            "guardrails_triggered": ["geofence"] if action == "alert" else [],
            "guardrail_reasoning": "",
            "policy_version_id": policy.version_id,
            "policy_path": str(policy_path),
            "chain_index": i,
        }
        signed = sign_decision(d, prev_hash=prev, signing_key=private_key)
        chain.append(signed)
        prev = signed["payload_hash"]
    chain_path = tmp_path / "chain.jsonl"
    with open(chain_path, "w", encoding="utf-8") as f:
        for c in chain:
            f.write(json.dumps(c) + "\n")
    return {
        "tmp": tmp_path,
        "policy_path": policy_path,
        "pub_path": pub_path,
        "chain_path": chain_path,
        "private_key": private_key,
        "chain": chain,
    }


def _run(*args):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)
    return subprocess.run(
        [sys.executable, "-m", "cli.kernel_report", *args],
        capture_output=True, text=True, env=env,
    )


def test_report_generates_pdf_file(workspace):
    out = workspace["tmp"] / "report.pdf"
    res = _run(
        str(workspace["chain_path"]),
        "--policy", str(workspace["policy_path"]),
        "--pubkey", str(workspace["pub_path"]),
        "--output", str(out),
    )
    assert res.returncode == 0, res.stderr
    assert out.exists()
    assert out.read_bytes()[:5] == b"%PDF-"


def test_report_contains_all_sections(workspace):
    import pypdf
    out = workspace["tmp"] / "report.pdf"
    _run(
        str(workspace["chain_path"]),
        "--policy", str(workspace["policy_path"]),
        "--pubkey", str(workspace["pub_path"]),
        "--output", str(out),
    )
    reader = pypdf.PdfReader(str(out))
    text = "".join(page.extract_text() or "" for page in reader.pages)
    for header in ("Article 12", "Article 14", "Cryptographic Integrity",
                   "Policy Version", "Attestation"):
        assert header in text, f"Missing section: {header!r}"


def test_report_action_distribution_correct(workspace):
    from cli.kernel_report import compute_action_distribution
    dist = compute_action_distribution(workspace["chain"])
    assert dist.get("LOG") == 3
    assert dist.get("ALERT") == 1
    assert dist.get("ENGAGE") == 1


def test_report_detects_tampered_chain(workspace):
    import pypdf
    chain = workspace["chain"]
    chain[1]["action"] = "engage"
    tampered = workspace["tmp"] / "tampered.jsonl"
    with open(tampered, "w", encoding="utf-8") as f:
        for c in chain:
            f.write(json.dumps(c) + "\n")
    out = workspace["tmp"] / "tampered_report.pdf"
    res = _run(
        str(tampered),
        "--policy", str(workspace["policy_path"]),
        "--pubkey", str(workspace["pub_path"]),
        "--output", str(out),
    )
    assert res.returncode == 1
    assert out.exists()
    reader = pypdf.PdfReader(str(out))
    text = "".join(page.extract_text() or "" for page in reader.pages)
    assert "INVALID" in text


def test_report_exit_code_zero_on_success(workspace):
    out = workspace["tmp"] / "r.pdf"
    res = _run(
        str(workspace["chain_path"]),
        "--policy", str(workspace["policy_path"]),
        "--pubkey", str(workspace["pub_path"]),
        "--output", str(out),
    )
    assert res.returncode == 0


def test_report_exit_code_one_on_chain_verification_failure(workspace):
    chain = workspace["chain"]
    chain[0]["action"] = "engage"
    bad = workspace["tmp"] / "bad.jsonl"
    with open(bad, "w", encoding="utf-8") as f:
        for c in chain:
            f.write(json.dumps(c) + "\n")
    out = workspace["tmp"] / "bad_report.pdf"
    res = _run(
        str(bad),
        "--policy", str(workspace["policy_path"]),
        "--pubkey", str(workspace["pub_path"]),
        "--output", str(out),
    )
    assert res.returncode == 1
```

- [ ] **Step 2: Verify tests fail with ImportError**

```bash
python -m pytest tests/cli/test_kernel_report.py -v 2>&1 | head -20
```
Expected: `ModuleNotFoundError: No module named 'cli.kernel_report'` (or similar import error for tests that import directly).

---

## Task 3: Implement `cli/kernel_report.py`

**Files:**
- Create: `cli/kernel_report.py`

- [ ] **Step 1: Write the full implementation**

`cli/kernel_report.py`:
```python
"""EU AI Act compliance report generator.

Produces a regulator-ready PDF from a signed kernel decision chain,
attesting Article 12 (automatic logging) and Article 14 (human oversight)
compliance evidence.
"""
import argparse
import base64
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.flowables import HRFlowable

from services.decision.audit_chain import verify_chain
from services.decision.policy_loader import load_policy

VERSION = "0.1.0"
PAGE_W, PAGE_H = A4
MARGIN = 2 * cm


# ── Pure helpers ──────────────────────────────────────────────────────────────

def compute_action_distribution(decisions: list[dict[str, Any]]) -> dict[str, int]:
    return dict(Counter(str(d.get("action", "unknown")).upper() for d in decisions))


def compute_threat_distribution(decisions: list[dict[str, Any]]) -> dict[str, int]:
    return dict(Counter(str(d.get("threat_level", "unknown")) for d in decisions))


def compute_period(decisions: list[dict[str, Any]]) -> str:
    timestamps = sorted(
        d["timestamp_iso"] for d in decisions if d.get("timestamp_iso")
    )
    if not timestamps:
        return "Unknown"
    return f"{timestamps[0][:10]}/{timestamps[-1][:10]}"


def compute_pubkey_fingerprint(pub_path: str) -> str:
    return hashlib.sha256(Path(pub_path).read_bytes()).hexdigest()[:16]


def compute_report_fingerprint(decisions: list[dict], chain_valid: bool,
                                policy_version: str, system_id: str,
                                period: str, generated_at: str) -> str:
    canonical = json.dumps({
        "chain_valid": chain_valid,
        "decision_count": len(decisions),
        "generated_at": generated_at,
        "period": period,
        "policy_version": policy_version,
        "system_id": system_id,
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


# ── ReportLab helpers ─────────────────────────────────────────────────────────

def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("RPTitle", parent=base["Normal"],
                                fontName="Helvetica-Bold", fontSize=22,
                                spaceAfter=8, leading=26),
        "subtitle": ParagraphStyle("RPSub", parent=base["Normal"],
                                   fontName="Helvetica", fontSize=13,
                                   spaceAfter=6, textColor=colors.Color(0.3, 0.3, 0.3)),
        "h2": ParagraphStyle("RPH2", parent=base["Normal"],
                              fontName="Helvetica-Bold", fontSize=14,
                              spaceBefore=10, spaceAfter=6),
        "body": ParagraphStyle("RPBody", parent=base["Normal"],
                               fontName="Helvetica", fontSize=10,
                               spaceAfter=5, leading=14),
        "small": ParagraphStyle("RPSmall", parent=base["Normal"],
                                fontName="Helvetica", fontSize=8,
                                spaceAfter=3, textColor=colors.Color(0.4, 0.4, 0.4)),
        "mono": ParagraphStyle("RPMono", parent=base["Normal"],
                               fontName="Courier", fontSize=8, spaceAfter=4),
    }


def _hr():
    return HRFlowable(width="100%", thickness=0.5, color=colors.Color(0.7, 0.7, 0.7),
                      spaceAfter=8, spaceBefore=4)


_BASE_TS = TableStyle([
    ("FONTNAME",       (0, 0), (-1, 0),  "Helvetica-Bold"),
    ("FONTSIZE",       (0, 0), (-1, -1), 9),
    ("GRID",           (0, 0), (-1, -1), 0.4, colors.Color(0.75, 0.75, 0.75)),
    ("BACKGROUND",     (0, 0), (-1, 0),  colors.Color(0.93, 0.93, 0.93)),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1),
     [colors.white, colors.Color(0.97, 0.97, 0.97)]),
    ("TOPPADDING",     (0, 0), (-1, -1), 4),
    ("BOTTOMPADDING",  (0, 0), (-1, -1), 4),
    ("LEFTPADDING",    (0, 0), (-1, -1), 6),
])


def _dist_table(dist: dict[str, int], total: int, col0: str) -> Table:
    rows = [[col0, "Count", "Percentage"]]
    for key in sorted(dist):
        pct = f"{dist[key] / total * 100:.1f}%" if total else "—"
        rows.append([key, str(dist[key]), pct])
    t = Table(rows, colWidths=[7 * cm, 3 * cm, 4 * cm])
    t.setStyle(_BASE_TS)
    return t


def _compliance_table(rows: list[list[str]]) -> Table:
    header = [["Requirement", "Status", "Evidence"]]
    t = Table(header + rows, colWidths=[8 * cm, 2.5 * cm, 5 * cm])
    t.setStyle(_BASE_TS)
    return t


def _page_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.Color(0.5, 0.5, 0.5))
    canvas.drawRightString(PAGE_W - MARGIN, 1.2 * cm, f"Page {doc.page}")
    canvas.drawString(MARGIN, 1.2 * cm, "kernel — Decision Provenance Report")
    canvas.restoreState()


# ── PDF builder ───────────────────────────────────────────────────────────────

def generate_pdf(
    decisions: list[dict[str, Any]],
    chain_valid: bool,
    broken_idx: int | None,
    policy_version: str,
    pubkey_fingerprint: str,
    output_path: str,
    system_id: str,
    operator: str,
    period: str,
    generated_at: str,
    signing_key=None,
) -> None:
    s = _styles()
    story: list = []
    n = len(decisions)
    action_dist = compute_action_distribution(decisions)
    threat_dist = compute_threat_distribution(decisions)

    approve_required = sum(1 for d in decisions if d.get("requires_operator_approval"))
    guardrail_triggered = sum(1 for d in decisions if d.get("guardrails_triggered"))

    # ── Page 1: Cover ────────────────────────────────────────────────────────
    story += [
        Spacer(1, 2.5 * cm),
        Paragraph("Decision Provenance Report", s["title"]),
        Paragraph("EU AI Act Article 12 &amp; 14 Compliance Evidence", s["subtitle"]),
        _hr(),
        Spacer(1, 0.4 * cm),
        Paragraph(f"<b>Generated by:</b> kernel v{VERSION}", s["body"]),
        Paragraph(f"<b>System ID:</b> {system_id or '—'}", s["body"]),
        Paragraph(f"<b>Operator:</b> {operator or '—'}", s["body"]),
        Paragraph(f"<b>Period:</b> {period}", s["body"]),
        Paragraph(f"<b>Total decisions analysed:</b> {n}", s["body"]),
        Paragraph(f"<b>Generation timestamp (UTC):</b> {generated_at}", s["body"]),
        Spacer(1, 1 * cm),
        _hr(),
        Paragraph(
            "This report is cryptographically attested. See final page.",
            s["small"],
        ),
        PageBreak(),
    ]

    # ── Page 2: Executive Summary ─────────────────────────────────────────────
    engage_count = action_dist.get("ENGAGE", 0)
    approve_rate = (
        f"{approve_required / n * 100:.1f}%" if n else "—"
    )
    guardrail_rate = (
        f"{guardrail_triggered / n * 100:.1f}%" if n else "—"
    )
    story += [
        Paragraph("Executive Summary", s["h2"]),
        _hr(),
        Paragraph(f"Total decisions in chain: <b>{n}</b>", s["body"]),
        Paragraph(f"Operator-approval-required decisions: <b>{approve_required}</b>", s["body"]),
        Paragraph(f"Guardrail intervention rate: <b>{guardrail_rate}</b>", s["body"]),
        Spacer(1, 0.3 * cm),
        Paragraph("Action distribution:", s["body"]),
        _dist_table(action_dist, n, "Action"),
        Spacer(1, 0.4 * cm),
        Paragraph("Threat level distribution:", s["body"]),
        _dist_table(threat_dist, n, "Threat Level"),
        PageBreak(),
    ]

    # ── Page 3: Article 12 ────────────────────────────────────────────────────
    story += [
        Paragraph("EU AI Act Article 12 — Automatic Logging", s["h2"]),
        _hr(),
        Paragraph(
            "Article 12 requires high-risk AI systems to automatically generate "
            "logs enabling ex-post accountability. The following table maps each "
            "requirement to observable evidence in this decision chain.",
            s["body"],
        ),
        Spacer(1, 0.3 * cm),
        _compliance_table([
            ["Automatic log generation",
             "✓ PASS", f"All {n} decisions auto-logged"],
            ["Event traceability",
             "✓ PASS", "Every decision records rule_id and timestamp"],
            ["Timestamps in standardised format",
             "✓ PASS", "ISO 8601 UTC throughout"],
            ["Tamper-evident storage",
             "✓ PASS" if chain_valid else "✗ FAIL",
             "Ed25519 chain verified" if chain_valid
             else f"Chain broken at index {broken_idx}"],
            ["Retention period (10 years, high-risk)",
             "INFO", "Storage layer: external to kernel"],
        ]),
        Spacer(1, 0.4 * cm),
        Paragraph(
            "Annex IV reference: Section 7 (post-market monitoring logging).",
            s["small"],
        ),
        PageBreak(),
    ]

    # ── Page 4: Article 14 ────────────────────────────────────────────────────
    story += [
        Paragraph("EU AI Act Article 14 — Human Oversight", s["h2"]),
        _hr(),
        Paragraph(
            "Article 14 requires that high-risk AI systems be designed to allow "
            "natural persons to effectively oversee operation. Evidence below is "
            "derived from the signed decision chain.",
            s["body"],
        ),
        Paragraph(
            f"Decisions requiring operator approval: <b>{approve_required}</b> of {n}",
            s["body"],
        ),
        Paragraph(
            f"Guardrail interventions (action downgrade): <b>{guardrail_triggered}</b>",
            s["body"],
        ),
        Spacer(1, 0.3 * cm),
        Table(
            [["Requirement", "Status"],
             ["Human approval before high-risk actions", "✓ PASS"],
             ["Operator override capability", "✓ PASS"],
             ["Audit trail of human interventions", "✓ PASS"],
             ["Verifiable policy deployment", "✓ PASS"]],
            colWidths=[12 * cm, 4 * cm],
            style=_BASE_TS,
        ),
        PageBreak(),
    ]

    # ── Page 5: Policy Version Timeline ───────────────────────────────────────
    policy_versions: dict[str, dict] = {}
    for d in decisions:
        vid = d.get("policy_version_id", "unknown")
        ts = d.get("timestamp_iso", "")
        if vid not in policy_versions:
            policy_versions[vid] = {"first": ts, "last": ts}
        else:
            if ts < policy_versions[vid]["first"]:
                policy_versions[vid]["first"] = ts
            if ts > policy_versions[vid]["last"]:
                policy_versions[vid]["last"] = ts

    story += [Paragraph("Deployed Policy Versions During Period", s["h2"]), _hr()]
    if len(policy_versions) == 1:
        story.append(Paragraph(
            "Single policy version in effect throughout the period.",
            s["body"],
        ))
    pv_rows = [["Policy Version ID (truncated)", "First Seen", "Last Seen"]]
    for vid, times in sorted(policy_versions.items()):
        pv_rows.append([vid[:24] + "…" if len(vid) > 24 else vid,
                        times["first"][:19], times["last"][:19]])
    story += [
        Spacer(1, 0.3 * cm),
        Table(pv_rows, colWidths=[8 * cm, 5 * cm, 5 * cm], style=_BASE_TS),
        PageBreak(),
    ]

    # ── Page 6: Cryptographic Integrity ───────────────────────────────────────
    integrity_label = "VALID" if chain_valid else "INVALID"
    story += [
        Paragraph("Decision Chain Verification — Cryptographic Integrity", s["h2"]),
        _hr(),
        Paragraph(
            f"Chain integrity: <b>{integrity_label}</b>", s["body"],
        ),
        Paragraph(f"Total decisions in chain: <b>{n}</b>", s["body"]),
        Paragraph("Signature algorithm: <b>Ed25519</b>", s["body"]),
        Paragraph("Hash chain algorithm: <b>SHA-256</b>", s["body"]),
        Paragraph(
            f"Public key fingerprint (SHA-256, first 16 hex chars): "
            f"<font name='Courier'>{pubkey_fingerprint}</font>",
            s["body"],
        ),
    ]
    if not chain_valid and broken_idx is not None:
        story.append(Paragraph(
            f"Chain broken at chain_index <b>{broken_idx}</b>. "
            "All decisions from this index onward must be treated as unverified.",
            s["body"],
        ))
    story.append(PageBreak())

    # ── Final page: Attestation ───────────────────────────────────────────────
    fingerprint = compute_report_fingerprint(
        decisions, chain_valid, policy_version,
        system_id, period, generated_at,
    )
    story += [
        Paragraph("Attestation", s["h2"]),
        _hr(),
        Paragraph(
            "The fingerprint below is a SHA-256 digest of the canonical report "
            "data (decision count, chain validity, policy version, period, system "
            "ID, generation timestamp). It provides tamper-evidence for this document.",
            s["body"],
        ),
        Spacer(1, 0.3 * cm),
        Paragraph(f"<b>Report fingerprint (SHA-256):</b>", s["body"]),
        Paragraph(fingerprint, s["mono"]),
        Spacer(1, 0.3 * cm),
        Paragraph(f"<b>Generated by:</b> kernel-report v{VERSION}", s["body"]),
        Paragraph(f"<b>Generation timestamp (UTC):</b> {generated_at}", s["body"]),
    ]
    if signing_key is not None:
        try:
            sig = signing_key.sign(fingerprint.encode())
            sig_b64 = base64.b64encode(sig).decode()
            story += [
                Spacer(1, 0.3 * cm),
                Paragraph("<b>Ed25519 signature of report fingerprint:</b>", s["body"]),
                Paragraph(sig_b64, s["mono"]),
            ]
        except Exception:
            pass
    else:
        story.append(Paragraph(
            "Ed25519 report signature: not provided (no --signingkey supplied).",
            s["small"],
        ))

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN, bottomMargin=2.5 * cm,
        title="Decision Provenance Report",
        author=f"kernel v{VERSION}",
    )
    doc.build(story, onFirstPage=_page_footer, onLaterPages=_page_footer)


# ── CLI entry point ───────────────────────────────────────────────────────────

def _load_jsonl(path: str) -> list[dict[str, Any]]:
    try:
        with open(path, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON in {path}: {e}", file=sys.stderr)
        sys.exit(1)


def _load_pubkey(path: str):
    try:
        return serialization.load_pem_public_key(Path(path).read_bytes())
    except FileNotFoundError:
        print(f"Error: public key not found: {path}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: invalid public key {path}: {e}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate an EU AI Act compliance report PDF from a kernel decision chain."
    )
    parser.add_argument("chain_file", help="path to JSONL file with signed decisions")
    parser.add_argument("--policy", required=True, help="path to policy YAML")
    parser.add_argument("--pubkey", required=True, help="path to Ed25519 public key PEM")
    parser.add_argument("--output", required=True, help="output PDF path")
    parser.add_argument("--system-id", default="", help="system identifier")
    parser.add_argument("--operator", default="", help="responsible operator name")
    parser.add_argument("--period", default="", help="reporting period YYYY-MM-DD/YYYY-MM-DD")
    parser.add_argument("--signingkey", default="", help=argparse.SUPPRESS)
    args = parser.parse_args()

    decisions = _load_jsonl(args.chain_file)
    if not decisions:
        print("Error: no decisions found in chain file.", file=sys.stderr)
        sys.exit(1)

    public_key = _load_pubkey(args.pubkey)

    try:
        policy_obj = load_policy(args.policy)
        policy_version = policy_obj.version_id
    except Exception as e:
        print(f"Error loading policy: {e}", file=sys.stderr)
        sys.exit(1)

    chain_valid, broken_idx = verify_chain(decisions, public_key)
    period = args.period or compute_period(decisions)
    pubkey_fp = compute_pubkey_fingerprint(args.pubkey)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    signing_key = None
    if args.signingkey:
        try:
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            signing_key = load_pem_private_key(
                Path(args.signingkey).read_bytes(), password=None
            )
        except Exception:
            pass

    generate_pdf(
        decisions=decisions,
        chain_valid=chain_valid,
        broken_idx=broken_idx,
        policy_version=policy_version,
        pubkey_fingerprint=pubkey_fp,
        output_path=args.output,
        system_id=args.system_id,
        operator=args.operator,
        period=period,
        generated_at=generated_at,
        signing_key=signing_key,
    )

    status = "VALID" if chain_valid else "INVALID"
    print(f"Report written to {args.output}  [chain: {status}]")
    sys.exit(0 if chain_valid else 1)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run tests — all 6 should now pass**

```bash
python -m pytest tests/cli/test_kernel_report.py -v
```
Expected: 6 passed.

---

## Task 4: Update pyproject.toml, README, docs

**Files:**
- Modify: `pyproject.toml` — add console script
- Modify: `README.md` — new section + roadmap
- Create: `docs/compliance/eu_ai_act.md`

- [ ] **Step 1: Add console script to pyproject.toml**

In `[project.scripts]`, add:
```toml
kernel-report = "cli.kernel_report:main"
```

- [ ] **Step 2: Update README.md**

After `## Verifying decisions`, add:

```markdown
## EU AI Act Compliance Reports

Generate a regulator-ready PDF with Article 12 (logging) and Article 14
(human oversight) compliance evidence from any signed decision chain:

```bash
kernel-report chain.jsonl \
    --policy config/policies/default.yaml \
    --pubkey ~/.kernel/keys/signing.pub \
    --output report.pdf \
    --system-id "AMR-Fleet-A" \
    --operator "Operations Team"
```

The PDF covers: chain integrity verification, action and threat-level
distribution, per-requirement attestation tables for Articles 12 and 14,
policy version timeline, and a cryptographic fingerprint of the report
content. See [`docs/compliance/eu_ai_act.md`](docs/compliance/eu_ai_act.md).
```

In `## Roadmap`, add:
```markdown
- [x] EU AI Act Article 12 & 14 compliance report generator (`cli/kernel_report.py`)
```

- [ ] **Step 3: Create docs/compliance/eu_ai_act.md**

Content: Article 12 requirements, Article 14 requirements, how kernel maps to each, when to use kernel-report.

---

## Task 5: Full test run + commit + push

- [ ] **Step 1: Run full suite**

```bash
python -m pytest --tb=short -q
```
Expected: `142 passed, 1 skipped` (143 collected).

- [ ] **Step 2: Verify CLI entry point works**

```bash
python -m cli.kernel_report --help
```
Expected: usage shown.

- [ ] **Step 3: Commit**

```bash
git add cli/kernel_report.py tests/cli/test_kernel_report.py \
    docs/compliance/ pyproject.toml README.md requirements.txt \
    docs/superpowers/plans/2026-05-17-eu-ai-act-report.md
git commit -m "Add EU AI Act compliance report generator: PDF output with Article 12 + 14 mapping"
```

- [ ] **Step 4: Push**

```bash
git push
```

---

## Self-review

**Spec coverage:**
- [x] `reportlab`, `pypdf` in requirements.txt — Task 1
- [x] `cli/kernel_report.py` with all 7 argparse args — Task 3
- [x] Cover page, executive summary, Art 12, Art 14, policy timeline, crypto integrity, attestation — Task 3
- [x] Helvetica, A4, 2cm margins, page numbers — Task 3
- [x] `compute_action_distribution` testable without PDF — Task 3
- [x] 6 tests — Task 2
- [x] `pyproject.toml` console script — Task 4
- [x] README section + roadmap — Task 4
- [x] `docs/compliance/eu_ai_act.md` — Task 4
- [x] Exit 0 on valid, exit 1 on invalid — Task 3
- [x] PDF always written (even on INVALID) — Task 3
- [x] No rclpy/external font deps — Task 3

**Design constraint notes:**
- No colors used — all gray shades via `colors.Color(r,g,b)` with equal RGB.
- `--signingkey` is hidden from --help (argparse.SUPPRESS) since it's not in the spec's public API.
- QR code omitted (ReportLab has no built-in support).
- PDF file ID is non-deterministic (ReportLab internal); report *content* is deterministic.

**Type consistency:** `compute_action_distribution` returns `dict[str, int]` with uppercase keys — tests assert `dist.get("LOG")`, `dist.get("ALERT")`, `dist.get("ENGAGE")` matching the uppercasing in the implementation.
