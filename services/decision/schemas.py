"""Decision layer schemas — SGLang-style constrained output compatible.

All decisions are bounded by ENUMs — cannot prevent LLM hallucination
but provides fail-safe through schema validation. The rule engine (decision
policy) always has the final say.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class ThreatLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(str, Enum):
    LOG = "log"                # record only
    ALERT = "alert"            # alert the operator
    ENGAGE = "engage"          # initiate actuator / response (after human approval)
    HANDOFF = "handoff"        # hand off to another system/operator


class DecisionSource(str, Enum):
    RULE_ENGINE = "rule_engine"
    LLM_ADVISOR = "llm_advisor"
    OPERATOR = "operator"


class ThreatAssessment(BaseModel):
    """Anomaly assessment of a fusion track.

    Input-based; deterministic scoring, not LLM.
    """
    track_id: str
    threat_level: ThreatLevel
    score: float = Field(ge=0.0, le=1.0)
    reasoning: str = Field(max_length=500)

    # Triggering factors (for audit trail)
    inside_protected_zone: bool = False
    unknown_transponder: bool = False
    aggressive_speed: bool = False
    aggressive_heading: bool = False
    confidence_exceeds_threshold: bool = False


class Decision(BaseModel):
    """Final action decision — produced by the rule engine."""
    track_id: str
    action: Action
    threat_level: ThreatLevel
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = Field(max_length=500)
    source: DecisionSource
    roe_reference: str | None = None  # which policy rule triggered
    requires_operator_approval: bool = True  # default True for ENGAGE
    timestamp_iso: str

    # Audit trail — store LLM output without truncation
    llm_raw_response: dict | None = None      # Claude tool_use input (raw)
    llm_provider: str | None = None           # "anthropic" | "ollama"
    llm_model: str | None = None              # model name
    guardrails_triggered: list[str] = Field(default_factory=list)
    guardrail_reasoning: str = ""             # guardrail explanations (not truncated into reasoning)


class ROERule(BaseModel):
    """Single decision policy rule (Rules of Engagement schema compatible)."""
    rule_id: str
    description: str
    when_threat_level: ThreatLevel
    when_inside_zone: bool | None = None  # None = don't care
    requires_operator_approval: bool = True
    action: Action
    enabled: bool = True
