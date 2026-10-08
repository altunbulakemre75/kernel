"""EU AI Act evidence report.

Produces a PDF of checks run on a signed Kyvern decision chain, mapped to the
EU AI Act Articles they support: Article 12 (record-keeping) and Article 14
(human oversight). Each row is computed from the chain or says that the chain
cannot show it. The report supports an assessment; it does not establish
conformity (Article 43).
"""
import argparse
import base64
import hashlib
import importlib.metadata
import json
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

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

from services.decision.audit_chain import (
    Keyring,
    PolicyCheck,
    check_policy_binding,
    record_type_of,
    verify_chain,
)
from services.decision.policy_loader import load_policy

try:
    # Single source of truth: the version in pyproject.toml, via the installed metadata.
    VERSION = importlib.metadata.version("kyvern")
except importlib.metadata.PackageNotFoundError:  # running from a source tree without an install
    VERSION = "unknown"
PAGE_W, PAGE_H = A4
MARGIN = 2 * cm


# ── Pure helpers ──────────────────────────────────────────────────────────────

def split_records(records: list[dict[str, Any]]) -> tuple[list[dict], list[dict]]:
    """(Decisions, RuntimeEvents), each in chain order."""
    decisions = [r for r in records if record_type_of(r) == "decision"]
    events = [r for r in records if record_type_of(r) == "runtime_event"]
    return decisions, events


def compute_action_distribution(records: list[dict[str, Any]]) -> dict[str, int]:
    """Action counts over Decisions; RuntimeEvents have no action."""
    decisions, _ = split_records(records)
    return dict(Counter(str(d.get("action", "unknown")).upper() for d in decisions))


def compute_threat_distribution(records: list[dict[str, Any]]) -> dict[str, int]:
    """Threat level counts over Decisions."""
    decisions, _ = split_records(records)
    return dict(Counter(str(d.get("threat_level", "unknown")) for d in decisions))


def compute_event_distribution(records: list[dict[str, Any]]) -> dict[str, int]:
    """RuntimeEvent counts by event_type."""
    _, events = split_records(records)
    return dict(Counter(str(e.get("event_type", "unknown")) for e in events))


def compute_period(decisions: list[dict[str, Any]]) -> str:
    # Text only: a tampered record may hold any JSON value here.
    timestamps = sorted(
        d["timestamp_iso"] for d in decisions
        if isinstance(d.get("timestamp_iso"), str) and d["timestamp_iso"]
    )
    if not timestamps:
        return "Unknown"
    return f"{timestamps[0][:10]}/{timestamps[-1][:10]}"


def compute_report_fingerprint(
    decisions: list[dict],
    chain_valid: bool,
    policy_version: str,
    system_id: str,
    period: str,
    generated_at: str,
    runtime_event_count: int = 0,
    policy_binding_ok: bool | None = None,
    checks: dict[str, str] | None = None,
) -> str:
    canonical = json.dumps(
        {
            "chain_valid": chain_valid,
            "checks": checks,
            "decision_count": len(decisions),
            "generated_at": generated_at,
            "period": period,
            "policy_binding_ok": policy_binding_ok,
            "policy_version": policy_version,
            "runtime_event_count": runtime_event_count,
            "system_id": system_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


# ── Evidence checks ───────────────────────────────────────────────────────────

PASS, FAIL, NOT_ASSESSED, NOT_APPLICABLE, INFO = "PASS", "FAIL", "NOT ASSESSED", "N/A", "INFO"


@dataclass(frozen=True)
class Check:
    """One row of the Article 12/14 tables: a check run on the chain and its result.

    status is PASS or FAIL when the check ran, NOT ASSESSED when the chain cannot
    show it, N/A when there was nothing to check, INFO for a figure that is not a
    pass/fail claim.
    """

    id: str
    article: str   # "12" or "14": the table the row belongs to
    label: str
    supports: str  # the Article(s) this evidence supports
    status: str
    evidence: str


def _parse_utc(ts: Any) -> datetime | None:
    """The timestamp as an aware datetime, or None if it is not ISO 8601 with an offset."""
    if not isinstance(ts, str):
        return None
    try:
        # Python 3.10's fromisoformat does not accept a trailing "Z".
        dt = datetime.fromisoformat(ts[:-1] + "+00:00" if ts.endswith("Z") else ts)
    except ValueError:
        return None
    return dt if dt.utcoffset() is not None else None


def _has_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def compute_checks(
    records: list[dict[str, Any]],
    *,
    chain_valid: bool,
    broken_idx: int | None,
    policy_check: PolicyCheck | None,
    generated_at: datetime,
) -> list[Check]:
    """Run the report's checks on the chain.

    Records of a chain that failed integrity are not evidence, so the checks
    computed from them are NOT ASSESSED.
    """
    decisions, events = split_records(records)
    n = len(decisions)
    unverified = "Chain integrity failed, so its records are unverified."
    checks: list[Check] = []

    def add(id_: str, article: str, label: str, supports: str, status: str, evidence: str) -> None:
        checks.append(Check(id_, article, label, supports, status, evidence))

    def per_decision(id_: str, label: str, supports: str, fields: str, has) -> None:
        if not chain_valid:
            add(id_, "12", label, supports, NOT_ASSESSED, unverified)
        elif n == 0:
            add(id_, "12", label, supports, NOT_APPLICABLE, "No decisions in the chain.")
        else:
            lacking = sum(1 for d in decisions if not has(d))
            if lacking:
                add(id_, "12", label, supports, FAIL, f"{lacking} of {n} decisions lack {fields}.")
            else:
                add(id_, "12", label, supports, PASS, f"All {n} decisions record {fields}.")

    # Article 12: record-keeping
    label = "Every entry signed and hash-linked"
    if chain_valid:
        add("integrity", "12", label, "Art.12(1)", PASS,
            f"{len(records)} entries verified ({n} decisions, {len(events)} runtime events).")
    else:
        add("integrity", "12", label, "Art.12(1)", FAIL,
            f"Chain broken at index {broken_idx}; entries from there on are unverified.")
    per_decision(
        "risk_fields", "Each decision records its threat level, rule reference and guardrails",
        "Art.12(2)(a)", "threat_level, roe_reference and guardrails_triggered",
        lambda d: _has_text(d.get("threat_level")) and "roe_reference" in d
        and isinstance(d.get("guardrails_triggered"), list),
    )
    per_decision(
        "policy_recorded", "Each decision records the policy version it was made under",
        "Art.12(2)(b)", "policy_version_id", lambda d: _has_text(d.get("policy_version_id")),
    )
    per_decision(
        "operation_fields",
        "Each decision records its action, timestamp, approval flag and guardrail reasoning",
        "Art.12(2)(c)",
        "action, timestamp_iso, requires_operator_approval and guardrail_reasoning",
        lambda d: _has_text(d.get("action")) and _has_text(d.get("timestamp_iso"))
        and isinstance(d.get("requires_operator_approval"), bool) and "guardrail_reasoning" in d,
    )
    label = "Every entry's timestamp is ISO 8601 in UTC"
    parsed = [_parse_utc(r.get("timestamp_iso")) for r in records]
    if not chain_valid:
        add("timestamps", "12", label, "Art.12(1)", NOT_ASSESSED, unverified)
    else:
        bad = sum(1 for dt in parsed if dt is None or dt.utcoffset().total_seconds() != 0)
        if bad:
            add("timestamps", "12", label, "Art.12(1)", FAIL,
                f"{bad} of {len(records)} entries have a timestamp that is not ISO 8601 UTC.")
        else:
            add("timestamps", "12", label, "Art.12(1)", PASS, f"All {len(records)} entries.")
    add("automatic", "12", "Records generated automatically, without human action",
        "Art.12(1)", NOT_ASSESSED,
        "The chain cannot show how its records were produced. run_graph() appends each "
        "decision before returning it; whether every decision of the system is recorded "
        "depends on the integration.")
    label = "Logs kept for at least six months"
    supports = "Art.19(1), Art.26(6)"
    times = [dt.astimezone(timezone.utc) for dt in parsed if dt is not None]
    if not chain_valid:
        add("retention", "12", label, supports, NOT_ASSESSED, unverified)
    elif not times:
        add("retention", "12", label, supports, INFO, "No entry has a readable timestamp.")
    else:
        earliest = min(times)
        add("retention", "12", label, supports, INFO,
            f"Earliest entry {earliest:%Y-%m-%d} ({(generated_at - earliest).days} days before "
            "this report). Keeping logs for at least six months is the provider's and the "
            "deployer's storage policy; Kyvern does not manage it.")

    # Article 14: human oversight
    label = "ENGAGE decisions flagged as requiring operator approval"
    engage = [d for d in decisions if str(d.get("action", "")).lower() == "engage"]
    if not chain_valid:
        add("approval_flag", "14", label, "Art.14", NOT_ASSESSED, unverified)
    elif not engage:
        add("approval_flag", "14", label, "Art.14", NOT_APPLICABLE,
            "No ENGAGE decisions in the chain.")
    else:
        unflagged = sum(1 for d in engage if d.get("requires_operator_approval") is not True)
        if unflagged:
            add("approval_flag", "14", label, "Art.14", FAIL,
                f"{unflagged} of {len(engage)} ENGAGE decisions are not flagged.")
        else:
            add("approval_flag", "14", label, "Art.14", PASS,
                f"All {len(engage)} ENGAGE decisions are flagged. The chain records that "
                "approval was required, not that it was given.")
    label = "Human interventions recorded (decisions with source=operator)"
    by_operator = sum(1 for d in decisions if d.get("source") == "operator")
    if not chain_valid:
        add("operator_decisions", "14", label, "Art.14", NOT_ASSESSED, unverified)
    elif by_operator:
        add("operator_decisions", "14", label, "Art.14", INFO,
            f"{by_operator} decision(s) recorded with source=operator.")
    else:
        add("operator_decisions", "14", label, "Art.14", NOT_ASSESSED,
            "No decision recorded with source=operator; interventions made outside Kyvern "
            "are not visible in the chain.")
    add("override", "14", "An operator can override or stop the system", "Art.14(4)",
        NOT_ASSESSED, "A property of the deployed system; the chain cannot show it.")
    label = "Guardrail downgrades recorded"
    if not chain_valid:
        add("guardrails", "14", label, "Art.14", NOT_ASSESSED, unverified)
    elif n == 0:
        add("guardrails", "14", label, "Art.14", NOT_APPLICABLE, "No decisions in the chain.")
    else:
        downgraded = sum(1 for d in decisions if d.get("guardrails_triggered"))
        add("guardrails", "14", label, "Art.14", INFO,
            f"{downgraded} of {n} decisions were downgraded by a guardrail (automated "
            "checks, not human oversight).")
    label = "Verifiable policy deployment: decisions bound to a supplied policy"
    if policy_check is None:
        add("policy", "14", label, "Art.14", NOT_ASSESSED, "No policy was supplied.")
    elif policy_check.ok:
        add("policy", "14", label, "Art.14", PASS,
            f"All {policy_check.decision_count} decisions are bound to the supplied "
            "policy version(s).")
    else:
        add("policy", "14", label, "Art.14", FAIL, policy_check.reason() + ".")
    return checks


# ── ReportLab helpers ─────────────────────────────────────────────────────────

_GRAY_LIGHT = colors.Color(0.93, 0.93, 0.93)
_GRAY_ROW = colors.Color(0.97, 0.97, 0.97)
_GRAY_RULE = colors.Color(0.70, 0.70, 0.70)
_GRAY_TEXT = colors.Color(0.40, 0.40, 0.40)


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "RPTitle", parent=base["Normal"],
            fontName="Helvetica-Bold", fontSize=22,
            spaceAfter=8, leading=26,
        ),
        "subtitle": ParagraphStyle(
            "RPSub", parent=base["Normal"],
            fontName="Helvetica", fontSize=13,
            spaceAfter=6, textColor=_GRAY_TEXT,
        ),
        "h2": ParagraphStyle(
            "RPH2", parent=base["Normal"],
            fontName="Helvetica-Bold", fontSize=14,
            spaceBefore=10, spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "RPBody", parent=base["Normal"],
            fontName="Helvetica", fontSize=10,
            spaceAfter=5, leading=14,
        ),
        "small": ParagraphStyle(
            "RPSmall", parent=base["Normal"],
            fontName="Helvetica", fontSize=8,
            spaceAfter=3, textColor=_GRAY_TEXT,
        ),
        "mono": ParagraphStyle(
            "RPMono", parent=base["Normal"],
            fontName="Courier", fontSize=8, spaceAfter=4,
        ),
        "cell": ParagraphStyle(
            "RPCell", parent=base["Normal"],
            fontName="Helvetica", fontSize=8.5, leading=10.5,
        ),
    }


def _hr() -> HRFlowable:
    return HRFlowable(
        width="100%", thickness=0.5, color=_GRAY_RULE,
        spaceAfter=8, spaceBefore=4,
    )


_BASE_TS = TableStyle([
    ("FONTNAME",       (0, 0), (-1, 0),  "Helvetica-Bold"),
    ("FONTSIZE",       (0, 0), (-1, -1), 9),
    ("GRID",           (0, 0), (-1, -1), 0.4, _GRAY_RULE),
    ("BACKGROUND",     (0, 0), (-1, 0),  _GRAY_LIGHT),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _GRAY_ROW]),
    ("TOPPADDING",     (0, 0), (-1, -1), 4),
    ("BOTTOMPADDING",  (0, 0), (-1, -1), 4),
    ("LEFTPADDING",    (0, 0), (-1, -1), 6),
    ("VALIGN",         (0, 0), (-1, -1), "TOP"),
])


def _dist_table(dist: dict[str, int], total: int, col0: str) -> Table:
    rows = [[col0, "Count", "Percentage"]]
    for key in sorted(dist):
        pct = f"{dist[key] / total * 100:.1f}%" if total else "—"
        rows.append([key, str(dist[key]), pct])
    t = Table(rows, colWidths=[7 * cm, 3 * cm, 4 * cm])
    t.setStyle(_BASE_TS)
    return t


def _page_footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(_GRAY_TEXT)
    canvas.drawRightString(PAGE_W - MARGIN, 1.2 * cm, f"Page {doc.page}")
    canvas.drawString(MARGIN, 1.2 * cm, "Kyvern — Decision Provenance Report")
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
    signing_key: Any = None,
    policy_check: PolicyCheck | None = None,
) -> None:
    """Build the PDF. `decisions` is every chain record; RuntimeEvents are reported
    separately and left out of the decision figures.

    Paragraph text is ReportLab markup: text from the CLI or the chain goes through
    escape() so that it prints as written.
    """
    s = _styles()
    story: list = []
    records = decisions
    decisions, events = split_records(records)
    n = len(decisions)
    action_dist = compute_action_distribution(decisions)
    threat_dist = compute_threat_distribution(decisions)
    event_dist = compute_event_distribution(events)
    approve_required = sum(1 for d in decisions if d.get("requires_operator_approval"))
    guardrail_triggered = sum(1 for d in decisions if d.get("guardrails_triggered"))
    guardrail_rate = f"{guardrail_triggered / n * 100:.1f}%" if n else "—"
    try:
        report_time = datetime.strptime(generated_at, "%Y-%m-%d %H:%M:%S UTC").replace(
            tzinfo=timezone.utc,
        )
    except ValueError:
        report_time = datetime.now(timezone.utc)
    checks = compute_checks(
        records, chain_valid=chain_valid, broken_idx=broken_idx,
        policy_check=policy_check, generated_at=report_time,
    )

    # ── Page 1: Cover ─────────────────────────────────────────────────────────
    story += [
        Spacer(1, 2.5 * cm),
        Paragraph("Decision Provenance Report", s["title"]),
        Paragraph("Evidence for EU AI Act Articles 12 &amp; 14", s["subtitle"]),
        _hr(),
        Spacer(1, 0.4 * cm),
        Paragraph(f"<b>Generated by:</b> Kyvern v{VERSION}", s["body"]),
        Paragraph(f"<b>System ID:</b> {escape(system_id) or '—'}", s["body"]),
        Paragraph(f"<b>Operator:</b> {escape(operator) or '—'}", s["body"]),
        Paragraph(f"<b>Period:</b> {escape(period)}", s["body"]),
        Paragraph(f"<b>Total decisions analysed:</b> {n}", s["body"]),
        Paragraph(f"<b>Runtime events in chain:</b> {len(events)}", s["body"]),
        Paragraph(f"<b>Generation timestamp (UTC):</b> {generated_at}", s["body"]),
        Spacer(1, 1 * cm),
        _hr(),
        Paragraph(
            "Checks run on a signed decision chain. They support, but do not establish, "
            "conformity with the EU AI Act. The report's fingerprint is on the final page.",
            s["small"],
        ),
        PageBreak(),
    ]

    # ── Page 2: Executive Summary ─────────────────────────────────────────────
    story += [
        Paragraph("Executive Summary", s["h2"]),
        _hr(),
        Paragraph(f"Total decisions in chain: <b>{n}</b>", s["body"]),
        Paragraph(
            f"Decisions requiring operator approval: <b>{approve_required}</b>",
            s["body"],
        ),
        Paragraph(
            f"Guardrail intervention rate: <b>{guardrail_rate}</b>",
            s["body"],
        ),
        Spacer(1, 0.3 * cm),
        Paragraph("Action distribution:", s["body"]),
        _dist_table(action_dist, n, "Action"),
        Spacer(1, 0.4 * cm),
        Paragraph("Threat level distribution:", s["body"]),
        _dist_table(threat_dist, n, "Threat Level"),
    ]
    if events:
        story += [
            Spacer(1, 0.4 * cm),
            Paragraph(
                f"Runtime events in chain: <b>{len(events)}</b> "
                "(upstream evidence; not counted as decisions)",
                s["body"],
            ),
            _dist_table(event_dist, len(events), "Event Type"),
        ]
    story.append(PageBreak())

    # ── Pages 3–4: Articles 12 and 14 ─────────────────────────────────────────
    def check_table(article: str, with_supports: bool) -> Table:
        header = ["Check", "Supports", "Result", "Evidence"] if with_supports else [
            "Check", "Result", "Evidence",
        ]
        rows: list[list] = [header]
        for c in checks:
            if c.article != article:
                continue
            row = [Paragraph(escape(c.label), s["cell"])]
            if with_supports:
                row.append(Paragraph(escape(c.supports), s["cell"]))
            row += [
                Paragraph(f"<b>{c.status}</b>", s["cell"]),
                Paragraph(escape(c.evidence), s["cell"]),
            ]
            rows.append(row)
        widths = (
            [5 * cm, 2.6 * cm, 2.4 * cm, 6.5 * cm] if with_supports
            else [6 * cm, 2.4 * cm, 8.1 * cm]
        )
        return Table(rows, colWidths=widths, style=_BASE_TS, repeatRows=1)

    story += [
        Paragraph("EU AI Act Article 12 — Record-keeping", s["h2"]),
        _hr(),
        Paragraph(
            "Each row below is a check run on this chain. PASS and FAIL are the results "
            "of that check; NOT ASSESSED means the chain cannot show it; N/A and INFO are "
            "not pass/fail claims. A PASS is evidence that supports an assessment under "
            "the Article named; it does not establish conformity, which is assessed under "
            "Article 43.",
            s["body"],
        ),
        Paragraph(
            "Article 12(2) asks that the logs enable risk identification (Art.79(1)), "
            "post-market monitoring (Art.72) and operation monitoring (Art.26(5)).",
            s["body"],
        ),
        Spacer(1, 0.3 * cm),
        check_table("12", with_supports=True),
        Spacer(1, 0.4 * cm),
        Paragraph(
            "<b>Article 12(3) — out of scope for Kyvern:</b> Art.12(3) imposes "
            "additional logging requirements (period of use, reference database, "
            "input data per identification, persons involved in verification) that "
            "apply exclusively to remote biometric identification systems "
            "(Annex III §1(a)). Kyvern is an autonomous-systems decision layer — "
            "not a remote biometric identification system.",
            s["small"],
        ),
        Spacer(1, 0.2 * cm),
        Paragraph(
            "Reference: Regulation (EU) 2024/1689, Official Journal of the "
            "European Union, 12 July 2024.",
            s["small"],
        ),
        PageBreak(),
    ]

    story += [
        Paragraph("EU AI Act Article 14 — Human Oversight", s["h2"]),
        _hr(),
        Paragraph(
            "Article 14 asks that natural persons can effectively oversee a high-risk AI "
            "system. Most of that is a property of the deployed system; the checks below "
            "show what this chain records about it.",
            s["body"],
        ),
        Paragraph(
            f"Decisions flagged as requiring operator approval: <b>{approve_required}</b> of {n}",
            s["body"],
        ),
        Paragraph(
            f"Automated guardrail downgrades: <b>{guardrail_triggered}</b> of {n}",
            s["body"],
        ),
        Spacer(1, 0.3 * cm),
        check_table("14", with_supports=False),
    ]
    if policy_check is not None and not policy_check.ok:
        story.append(Paragraph(
            f"Verifiable policy deployment failed: {escape(policy_check.reason())}.",
            s["body"],
        ))
    story.append(PageBreak())

    # ── Page 5: Policy Version Timeline ───────────────────────────────────────
    policy_versions: dict[str, dict] = {}
    for d in decisions:
        vid = str(d.get("policy_version_id") or "(none recorded)")
        ts = d.get("timestamp_iso", "")
        if not isinstance(ts, str):
            ts = ""
        if vid not in policy_versions:
            policy_versions[vid] = {"first": ts, "last": ts}
        else:
            if ts < policy_versions[vid]["first"]:
                policy_versions[vid]["first"] = ts
            if ts > policy_versions[vid]["last"]:
                policy_versions[vid]["last"] = ts

    pv_rows = [["Policy Version ID (truncated)", "First Seen", "Last Seen"]]
    for vid, times in sorted(policy_versions.items()):
        short_vid = (vid[:22] + "…") if len(vid) > 23 else vid
        pv_rows.append([short_vid, times["first"][:19], times["last"][:19]])

    story += [
        Paragraph("Deployed Policy Versions During Period", s["h2"]),
        _hr(),
    ]
    if list(policy_versions) == ["(none recorded)"]:
        story.append(Paragraph(
            "No decision in the period records a policy version.",
            s["body"],
        ))
    elif len(policy_versions) == 1:
        story.append(Paragraph(
            "Single policy version in effect throughout the period.",
            s["body"],
        ))
    story += [
        Spacer(1, 0.3 * cm),
        Table(pv_rows, colWidths=[7 * cm, 5 * cm, 5 * cm], style=_BASE_TS),
        PageBreak(),
    ]

    # ── Page 6: Cryptographic Integrity ───────────────────────────────────────
    integrity_label = "VALID" if chain_valid else "INVALID"
    story += [
        Paragraph(
            "Decision Chain Verification — Cryptographic Integrity", s["h2"],
        ),
        _hr(),
        Paragraph(f"Chain integrity: <b>{integrity_label}</b>", s["body"]),
        Paragraph(f"Total decisions in chain: <b>{n}</b>", s["body"]),
        Paragraph(f"Runtime events in chain: <b>{len(events)}</b>", s["body"]),
        Paragraph("Signature algorithm: <b>Ed25519</b>", s["body"]),
        Paragraph("Hash chain algorithm: <b>SHA-256</b>", s["body"]),
        Paragraph(
            f"Signing key ID(s) (SHA-256 of the raw public key, first 16 hex chars): "
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
        runtime_event_count=len(events),
        policy_binding_ok=policy_check.ok if policy_check is not None else None,
        checks={c.id: c.status for c in checks},
    )
    story += [
        Paragraph("Attestation", s["h2"]),
        _hr(),
        Paragraph(
            "The fingerprint below is a SHA-256 digest of the canonical report "
            "data (decision and runtime event counts, chain validity, policy "
            "version(s) and binding check, the result of each check, period, system ID, "
            "generation timestamp). "
            "It provides tamper-evidence for this document.",
            s["body"],
        ),
        Spacer(1, 0.3 * cm),
        Paragraph("<b>Report fingerprint (SHA-256):</b>", s["body"]),
        Paragraph(fingerprint, s["mono"]),
        Spacer(1, 0.3 * cm),
        Paragraph(f"<b>Generated by:</b> kyvern-report v{VERSION}", s["body"]),
        Paragraph(f"<b>Generation timestamp (UTC):</b> {generated_at}", s["body"]),
    ]
    if signing_key is not None:
        try:
            sig = signing_key.sign(fingerprint.encode())
            sig_b64 = base64.b64encode(sig).decode()
            story += [
                Spacer(1, 0.3 * cm),
                Paragraph(
                    "<b>Ed25519 signature of report fingerprint:</b>", s["body"],
                ),
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
        author=f"Kyvern v{VERSION}",
    )
    doc.build(story, onFirstPage=_page_footer, onLaterPages=_page_footer)


# ── CLI ───────────────────────────────────────────────────────────────────────

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
        description="Generate an EU AI Act compliance report PDF from a Kyvern "
                    "decision chain.",
    )
    parser.add_argument("chain_file", help="path to JSONL file with signed decisions")
    parser.add_argument("--policy",    required=True, action="append",
                        help="path to a policy YAML; repeat for a chain that spans policy updates")
    parser.add_argument("--pubkey",    required=True, action="append",
                        help="path to an Ed25519 public key PEM; repeat for chains signed by several keys")
    parser.add_argument("--output",    required=True, help="output PDF path")
    parser.add_argument("--system-id", default="",   help="system identifier")
    parser.add_argument("--operator",  default="",   help="responsible operator name")
    parser.add_argument("--period",    default="",
                        help="reporting period YYYY-MM-DD/YYYY-MM-DD "
                             "(auto-detected from chain if omitted)")
    parser.add_argument("--signingkey", default="", help=argparse.SUPPRESS)
    args = parser.parse_args()

    decisions = _load_jsonl(args.chain_file)
    if not decisions:
        print("Error: no decisions found in chain file.", file=sys.stderr)
        sys.exit(1)

    public_key = Keyring([_load_pubkey(p) for p in args.pubkey])

    policies = []
    for path in args.policy:
        try:
            policies.append(load_policy(path))
        except Exception as e:
            print(f"Error loading policy {path}: {e}", file=sys.stderr)
            sys.exit(1)
    policy_version = ",".join(p.version_id for p in policies)

    chain_valid, broken_idx = verify_chain(decisions, public_key)
    policy_check = check_policy_binding(decisions, policies, broken_at=broken_idx)
    period = args.period or compute_period(decisions)
    pubkey_fp = ", ".join(public_key.ids())
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    signing_key = None
    if args.signingkey:
        try:
            from cryptography.hazmat.primitives.serialization import (
                load_pem_private_key,
            )
            signing_key = load_pem_private_key(
                Path(args.signingkey).read_bytes(), password=None,
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
        policy_check=policy_check,
    )

    status = "VALID" if chain_valid else "INVALID"
    policy_status = "OK" if policy_check.ok else "FAILED"
    print(f"Report written to {args.output}  [chain: {status}] [policy: {policy_status}]")
    if not policy_check.ok:
        print(f"Policy check failed: {policy_check.reason()}", file=sys.stderr)
    sys.exit(0 if chain_valid and policy_check.ok else 1)


if __name__ == "__main__":
    main()
