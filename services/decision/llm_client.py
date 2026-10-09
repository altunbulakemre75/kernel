"""LLM provider abstraction — Anthropic Claude primary, Ollama fallback.

Internet may be unavailable in field deployment. Tried in order:
  1. ANTHROPIC_API_KEY present → Claude API
  2. Ollama localhost:11434 available → local llama3.1
  3. Neither available → None (LLM advisor fully disabled)

Both providers return the same interface:
    LLMResponse(action, threat_level, confidence, reasoning, roe_reference, raw)
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any

import httpx

log = logging.getLogger(__name__)

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")


@dataclass
class LLMResponse:
    action: str                # "log" | "alert" | "handoff"  (ENGAGE prohibited)
    threat_level: str | None   # "low" | "medium" | "high" | "critical"; None if invalid
    confidence: float | None   # 0..1; None if invalid
    reasoning: str
    roe_reference: str | None
    raw: dict[str, Any]  # raw response — for audit trail
    provider: str        # "anthropic" | "ollama"
    model: str


# ── Schema definition (Claude tool + Ollama JSON schema) ──────────

DECISION_SCHEMA = {
    "type": "object",
    "properties": {
        "threat_level": {
            "type": "string",
            "enum": ["low", "medium", "high", "critical"],
        },
        "action": {
            "type": "string",
            "enum": ["log", "alert", "handoff"],   # ENGAGE prohibited for LLM
        },
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "reasoning": {"type": "string", "maxLength": 500},
        "roe_reference": {"type": "string"},
    },
    "required": ["threat_level", "action", "confidence", "reasoning"],
}


DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-6"


def _anthropic_model() -> str:
    return os.getenv("KYVERN_LLM_MODEL", DEFAULT_ANTHROPIC_MODEL)


def _is_probability(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return 0.0 <= float(value) <= 1.0  # False for NaN
    except OverflowError:  # an int too large for a float
        return False


def _assessment(answer: Any, provider: str, model: str) -> LLMResponse:
    """The advisor's answer as an LLMResponse, whatever shape it came in.

    Neither provider is guaranteed to follow DECISION_SCHEMA. A malformed answer is
    still the advisor's answer: it is returned (no fallback to another provider) and
    never raises. A value that does not fit the schema becomes None, and an action
    that does not fit becomes "log", which can never raise the rule engine's action.
    The reasoning starts with what did not fit, so the signed decision says so, and
    `raw` keeps the answer as given.
    """
    problems: list[str] = []
    if isinstance(answer, dict):
        fields: dict[str, Any] = answer
        raw = answer
    else:
        problems.append(f"not a JSON object ({type(answer).__name__})")
        fields, raw = {}, {"invalid_answer": answer}
    props = DECISION_SCHEMA["properties"]
    checks = {
        "action": lambda v: v in props["action"]["enum"],
        "threat_level": lambda v: v in props["threat_level"]["enum"],
        "confidence": _is_probability,
        "reasoning": lambda v: isinstance(v, str),
        "roe_reference": lambda v: isinstance(v, str),
    }
    values: dict[str, Any] = {}
    for name, fits in checks.items():
        if name not in fields:
            if fields and name in DECISION_SCHEMA["required"]:
                problems.append(f"{name} missing")
            values[name] = None
        elif not fits(fields[name]):
            problems.append(f"{name} invalid: {fields[name]!r:.40}")
            values[name] = None
        else:
            values[name] = fields[name]

    reasoning = (values["reasoning"] or "")[:500]
    if problems:
        log.warning("%s answer did not match the schema: %s", provider, "; ".join(problems))
        reasoning = f"[answer did not match the schema: {'; '.join(problems)}] {reasoning}".rstrip()
    return LLMResponse(
        action=values["action"] or "log",
        threat_level=values["threat_level"],
        confidence=float(values["confidence"]) if values["confidence"] is not None else None,
        reasoning=reasoning,
        roe_reference=values["roe_reference"],
        raw=raw, provider=provider, model=model,
    )


async def _try_anthropic(prompt: str) -> LLMResponse | None:
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    try:
        from anthropic import AsyncAnthropic
    except ImportError:
        log.debug("anthropic package not installed")
        return None

    client = AsyncAnthropic(api_key=api_key)
    model = _anthropic_model()
    tools: list[Any] = [{
        "name": "submit_assessment",
        "description": "Submit the advisor's assessment.",
        "input_schema": DECISION_SCHEMA,
    }]

    try:
        msg = await client.messages.create(
            model=model, max_tokens=512, tools=tools,
            tool_choice={"type": "tool", "name": "submit_assessment"},
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception as exc:
        log.warning("Claude API error: %s", exc)
        return None

    for block in msg.content:
        if block.type == "tool_use" and block.name == "submit_assessment":
            return _assessment(block.input, "anthropic", model)
    return None


async def _try_ollama(prompt: str) -> LLMResponse | None:
    """Ollama /api/generate endpoint — structured output via JSON format=json."""
    full_prompt = (
        prompt + "\n\nRespond ONLY with JSON matching this schema:\n"
        + json.dumps(DECISION_SCHEMA, indent=2)
    )
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(
                f"{OLLAMA_URL}/api/generate",
                json={"model": OLLAMA_MODEL, "prompt": full_prompt, "format": "json", "stream": False},
            )
            r.raise_for_status()
            data = r.json()
    except Exception as exc:
        log.debug("Ollama unavailable or error: %s", exc)
        return None

    response_text = data.get("response", "")
    try:
        parsed = json.loads(response_text)
    except json.JSONDecodeError:
        parsed = response_text  # recorded as an answer that is not a JSON object
    return _assessment(parsed, "ollama", OLLAMA_MODEL)


async def query_llm(prompt: str) -> LLMResponse | None:
    """Provider fallback: Anthropic → Ollama → None."""
    response = await _try_anthropic(prompt)
    if response is not None:
        return response
    response = await _try_ollama(prompt)
    if response is not None:
        return response
    return None
