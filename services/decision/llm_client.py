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
    action: str          # "log" | "alert" | "handoff"  (ENGAGE prohibited)
    threat_level: str    # "low" | "medium" | "high" | "critical"
    confidence: float
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


def _assessment(answer: Any, provider: str, model: str) -> LLMResponse | None:
    """The advisor's answer as an LLMResponse; None if it is not a JSON object.

    Neither provider is guaranteed to follow DECISION_SCHEMA, and a malformed answer
    must not stop the decision: missing or invalid values get a safe default
    (an action outside the schema becomes "log", which can never raise the rule
    engine's action). The answer is kept as given in `raw`.
    """
    if not isinstance(answer, dict):
        log.warning("%s answer is not an object — ignored", provider)
        return None
    schema = DECISION_SCHEMA["properties"]
    action = answer.get("action", "log")
    if action not in schema["action"]["enum"]:
        log.warning("%s returned invalid action: %s — downgrading to 'log'", provider, action)
        action = "log"
    threat_level = answer.get("threat_level", "low")
    if threat_level not in schema["threat_level"]["enum"]:
        threat_level = "low"
    try:
        confidence = float(answer.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    if not 0.0 <= confidence <= 1.0:
        confidence = 0.5
    roe_reference = answer.get("roe_reference")
    return LLMResponse(
        action=action,
        threat_level=threat_level,
        confidence=confidence,
        reasoning=str(answer.get("reasoning", ""))[:500],
        roe_reference=roe_reference if isinstance(roe_reference, str) else None,
        raw=answer, provider=provider, model=model,
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
        log.warning("Ollama JSON parse failed: %s", response_text[:200])
        return None

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
