from enum import Enum
from typing import Any

from pydantic import BaseModel


class AgentName(str, Enum):
    camera = "camera"


class TaskRequest(BaseModel):
    action: str
    payload: dict[str, Any] = {}


class AgentResult(BaseModel):
    ok: bool
    agent: AgentName
    action: str
    data: dict[str, Any]
    error: str = ""


class OrchestratorResponse(BaseModel):
    ok: bool
    decision: AgentName
    result: AgentResult
