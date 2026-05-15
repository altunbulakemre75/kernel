"""LLM advisor — optional, runs ALONGSIDE the rule engine, does not override.

Activation: KERNEL_DECISION_LLM_ENABLED=true env var (NIZAM_DECISION_LLM_ENABLED also works).
Packages: pip install "langgraph>=0.2" "anthropic>=0.40" "llama-index>=0.12"

Behaviour:
  1. Rule engine is always the authoritative decision source (safety-critical).
  2. LLM advises; its recommendation is reconciled with the rule engine → reconcile().
  3. Even if the LLM says "ENGAGE", if the rule engine says "ALERT" → ALERT wins.

This file is a SHELL — the real LangGraph implementation becomes
production-ready once packages are installed. If absent, returns placeholder.
"""
from __future__ import annotations

import logging
import os
from typing import Literal, TypedDict

from services.decision.schemas import (
    Action,
    Decision,
    DecisionSource,
    ThreatAssessment,
    ThreatLevel,
)

log = logging.getLogger(__name__)

LLMDecisionDict = TypedDict(
    "LLMDecisionDict",
    {
        "threat_level": Literal["low", "medium", "high", "critical"],
        "action": Literal["log", "alert", "engage", "handoff"],
        "confidence": float,
        "reasoning": str,
        "roe_reference": str,
    },
    total=False,
)


def is_llm_enabled() -> bool:
    return os.getenv("KERNEL_DECISION_LLM_ENABLED", os.getenv("NIZAM_DECISION_LLM_ENABLED", "false")).lower() == "true"


async def query_llm_advisor(
    track: dict, assessment: ThreatAssessment
) -> LLMDecisionDict | None:
    """Anomaly advisor query via Claude API — structured output.

    Returns None if Anthropic is not installed.
    Decision policy RAG integration: if available, doctrine context is added to the prompt.
    """
    if not is_llm_enabled():
        return None
    try:
        from anthropic import AsyncAnthropic  # noqa: PLC0415
    except ImportError:
        log.warning("anthropic package not installed — skipping LLM advisor")
        return None

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        log.warning("ANTHROPIC_API_KEY not set — skipping LLM advisor")
        return None

    # Optional: decision policy RAG context
    roe_context = ""
    try:
        from services.knowledge.roe_rag import ROERAG  # noqa: PLC0415

        rag = ROERAG()
        roe_results = rag.query(
            f"incident level {assessment.threat_level.value} "
            f"{'inside zone' if assessment.inside_protected_zone else 'outside zone'}"
        )
        if roe_results:
            roe_context = "\n\nRelevant policy:\n" + "\n".join(
                f"- [{r.rule_id or r.source}] {r.excerpt}" for r in roe_results[:2]
            )
    except Exception as exc:
        log.debug("Policy RAG query failed: %s", exc)

    # Structured output — Claude tool use
    tools = [{
        "name": "submit_assessment",
        "description": "Submit anomaly assessment with policy-compliant action recommendation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "threat_level": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                "action": {"type": "string", "enum": ["log", "alert", "handoff"]},  # ENGAGE is operator-only
                "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                "reasoning": {"type": "string", "maxLength": 300},
                "roe_reference": {"type": "string"},
            },
            "required": ["threat_level", "action", "confidence", "reasoning"],
        },
    }]

    prompt = (
        f"Autonomous system anomaly advisor. Track assessment.\n"
        f"Subject: id={track.get('track_id')} conf={track.get('confidence', 0):.2f}\n"
        f"Position: x={track.get('x', 0):.0f} y={track.get('y', 0):.0f} z={track.get('z', 0):.0f}\n"
        f"Velocity: vx={track.get('vx', 0):.1f} vy={track.get('vy', 0):.1f}\n"
        f"Sources: {track.get('sources', [])}\n"
        f"Entity ID: {track.get('uas_id') or 'unknown'}\n\n"
        f"Rule engine pre-assessment:\n"
        f"  incident_level={assessment.threat_level.value}\n"
        f"  score={assessment.score:.2f}\n"
        f"  reasoning={assessment.reasoning}\n"
        f"{roe_context}\n\n"
        "You are an advisor, not the decision maker. Submit your independent "
        "assessment via submit_assessment tool. NEVER recommend ENGAGE — only "
        "LOG, ALERT, or HANDOFF. Operators and rule engine control ENGAGE."
    )

    client = AsyncAnthropic(api_key=api_key)
    try:
        msg = await client.messages.create(
            model=os.getenv("NIZAM_LLM_MODEL", "claude-sonnet-4-6"),
            max_tokens=512,
            tools=tools,
            tool_choice={"type": "tool", "name": "submit_assessment"},
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception as exc:
        log.warning("Claude API call failed: %s", exc)
        return None

    for block in msg.content:
        if block.type == "tool_use" and block.name == "submit_assessment":
            return LLMDecisionDict(**block.input)
    return None


def reconcile(rule_decision: Decision, llm_hint: LLMDecisionDict | None) -> Decision:
    """Reconcile the LLM hint with the rule decision — SAFETY FIRST.

    Rules:
      1. If the rule engine did not say ENGAGE, the LLM can never trigger ENGAGE.
      2. If the rule engine said ALERT, the LLM may say HANDOFF (upgrade ok).
      3. If the rule engine said LOG, the LLM may say ALERT (upgrade ok).
      4. If the rule engine is more severe → the LLM cannot downgrade.
      5. LLM reasoning is APPENDED to the rule decision reasoning.
    """
    if llm_hint is None:
        return rule_decision

    rule_action = rule_decision.action
    llm_action_str = llm_hint.get("action", "log")
    llm_action = Action(llm_action_str)

    # Severity ordering (low to high)
    severity = {
        Action.LOG: 0,
        Action.ALERT: 1,
        Action.HANDOFF: 2,
        Action.ENGAGE: 3,
    }

    # LLM may only propose upward upgrades, never to ENGAGE
    final_action = rule_action
    if llm_action != Action.ENGAGE and severity[llm_action] > severity[rule_action]:
        final_action = llm_action

    merged_reasoning = f"{rule_decision.reasoning} | LLM: {llm_hint.get('reasoning', '')[:120]}"

    return Decision(
        track_id=rule_decision.track_id,
        action=final_action,
        threat_level=rule_decision.threat_level,  # rule engine level
        confidence=rule_decision.confidence,
        reasoning=merged_reasoning[:500],
        source=DecisionSource.RULE_ENGINE if final_action == rule_action else DecisionSource.LLM_ADVISOR,
        roe_reference=rule_decision.roe_reference,
        requires_operator_approval=rule_decision.requires_operator_approval or (final_action == Action.ENGAGE),
        timestamp_iso=rule_decision.timestamp_iso,
    )


# Re-export to prevent empty usage
__all__ = ["query_llm_advisor", "reconcile", "is_llm_enabled", "ThreatLevel"]
