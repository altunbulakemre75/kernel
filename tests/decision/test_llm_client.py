"""LLM client tests — Anthropic/Ollama fallback."""
from __future__ import annotations

import pytest

from services.decision.llm_client import DECISION_SCHEMA, LLMResponse


def test_schema_action_has_no_engage():
    """SAFETY: Claude should not be given ENGAGE option."""
    assert "log" in DECISION_SCHEMA["properties"]["action"]["enum"]
    assert "alert" in DECISION_SCHEMA["properties"]["action"]["enum"]
    assert "handoff" in DECISION_SCHEMA["properties"]["action"]["enum"]
    assert "engage" not in DECISION_SCHEMA["properties"]["action"]["enum"]


def test_schema_required_fields():
    req = set(DECISION_SCHEMA["required"])
    assert {"threat_level", "action", "confidence", "reasoning"}.issubset(req)


def test_llm_response_dataclass_structure():
    r = LLMResponse(
        action="alert", threat_level="high", confidence=0.9,
        reasoning="test", roe_reference="POL-3",
        raw={"x": 1}, provider="ollama", model="llama3",
    )
    assert r.action == "alert"
    assert r.raw == {"x": 1}


@pytest.mark.asyncio
async def test_query_llm_returns_none_when_no_provider(monkeypatch):
    """If neither Anthropic nor Ollama is available -> None."""
    from services.decision import llm_client

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    # Ollama fail et
    monkeypatch.setattr(llm_client, "OLLAMA_URL", "http://localhost:1")  # won't respond
    result = await llm_client.query_llm("test prompt")
    assert result is None


def test_anthropic_model_comes_from_the_kyvern_variable(monkeypatch):
    from services.decision import llm_client

    monkeypatch.delenv("KYVERN_LLM_MODEL", raising=False)
    monkeypatch.setenv("NIZAM_LLM_MODEL", "old-name")  # pre-rename name: ignored
    assert llm_client._anthropic_model() == llm_client.DEFAULT_ANTHROPIC_MODEL
    monkeypatch.setenv("KYVERN_LLM_MODEL", "claude-x")
    assert llm_client._anthropic_model() == "claude-x"


# ── Malformed advisor answers: neither provider may crash the decision ────────

def _fake_anthropic(monkeypatch, tool_input):
    """Make _try_anthropic() receive `tool_input` as Claude's submit_assessment call."""
    import sys
    from types import ModuleType, SimpleNamespace

    class _Messages:
        async def create(self, **_):
            block = SimpleNamespace(type="tool_use", name="submit_assessment", input=tool_input)
            return SimpleNamespace(content=[block])

    module = ModuleType("anthropic")
    module.AsyncAnthropic = lambda api_key: SimpleNamespace(messages=_Messages())  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "anthropic", module)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")


def _fake_ollama(monkeypatch, answer):
    import json

    from services.decision import llm_client

    class _Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"response": json.dumps(answer)}

    class _Client:
        def __init__(self, **_):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return False

        async def post(self, *_, **__):
            return _Response()

    monkeypatch.setattr(llm_client.httpx, "AsyncClient", _Client)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


@pytest.mark.asyncio
async def test_anthropic_answer_missing_fields_is_kept_and_flagged(monkeypatch, caplog):
    from services.decision.llm_client import query_llm

    _fake_anthropic(monkeypatch, {"action": "alert"})
    r = await query_llm("prompt")
    assert r is not None
    assert (r.provider, r.action, r.threat_level, r.confidence) == ("anthropic", "alert", None, None)
    assert r.raw == {"action": "alert"}
    assert r.reasoning.startswith("[answer did not match the schema: ")
    for missing in ("threat_level", "confidence", "reasoning"):
        assert missing in r.reasoning
    assert "did not match the schema" in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["anthropic", "ollama"])
@pytest.mark.parametrize("confidence", ["very", True, 1.5, 10**400],
                         ids=["text", "bool", "above_1", "too_large_for_float"])
async def test_invalid_answer_values_are_flagged_not_raised(monkeypatch, provider, confidence):
    from services.decision.llm_client import query_llm

    answer = {"action": "engage", "threat_level": "apocalyptic", "confidence": confidence,
              "reasoning": None, "roe_reference": ["R1"]}
    (_fake_anthropic if provider == "anthropic" else _fake_ollama)(monkeypatch, answer)
    r = await query_llm("prompt")
    assert r is not None
    assert (r.provider, r.action, r.threat_level, r.confidence, r.roe_reference) == (
        provider, "log", None, None, None
    )
    for field in ("action", "threat_level", "confidence", "reasoning", "roe_reference"):
        assert field in r.reasoning
    assert r.raw == answer


@pytest.mark.asyncio
async def test_an_answer_that_is_not_an_object_is_recorded_not_skipped(monkeypatch):
    """A bad answer is the advisor's answer: no fallback to another provider, no 'not consulted'."""
    from services.decision import llm_client

    _fake_anthropic(monkeypatch, ["alert"])
    asked_ollama = []

    async def _ollama(prompt):
        asked_ollama.append(prompt)

    monkeypatch.setattr(llm_client, "_try_ollama", _ollama)
    r = await llm_client.query_llm("prompt")
    assert asked_ollama == []
    assert r is not None
    assert (r.provider, r.action, r.raw) == ("anthropic", "log", {"invalid_answer": ["alert"]})
    assert "not a JSON object" in r.reasoning
