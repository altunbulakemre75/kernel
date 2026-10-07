import hashlib
import json
from typing import Any

from pydantic import BaseModel


class QLLMInstruction(BaseModel):
    ref_id: str
    extraction_prompt: str


class SandwichPlan(BaseModel):
    reasoning: str
    q_llm_instructions: list[QLLMInstruction]


class ToolInvocation(BaseModel):
    tool_name: str
    args: dict[str, Any] = {}


class SandwichDecision(BaseModel):
    reasoning: str
    tool_invocations: list[ToolInvocation] = []
    result: dict[str, Any] | None = None


class SandwichSchemaError(Exception):
    pass


class SandwichToolMisuseError(Exception):
    pass


def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def hash_dict(d: dict) -> str:
    return hashlib.sha256(
        json.dumps(d, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:16]
