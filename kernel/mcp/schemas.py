"""Pydantic input/output models for kernel-mcp tools and resources."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


# ── Tool inputs ──────────────────────────────────────────────────────────────

class QueryEventsInput(BaseModel):
    start_time: str | None = None
    end_time: str | None = None
    action: Literal["allow", "block", "flag"] | None = None
    threat_level: Literal["low", "medium", "high"] | None = None
    limit: int = Field(default=100, ge=1, le=1000)


class GetEventInput(BaseModel):
    event_id: int


class GetStatsInput(BaseModel):
    window: Literal["1h", "24h", "7d", "30d", "all"] = "24h"


class VerifyChainInput(BaseModel):
    start_id: int | None = None
    end_id: int | None = None


class SearchEventsInput(BaseModel):
    query: str
    limit: int = Field(default=50, ge=1, le=500)


# ── Tool outputs ─────────────────────────────────────────────────────────────

class EventSummary(BaseModel):
    id: int
    timestamp_iso: str
    action: str
    threat_level: str | None = None
    sig_valid: bool | None = None


class EventDetail(BaseModel):
    event: dict[str, Any]
    sig_valid: bool | None = None
    chain_link: Literal["OK", "BROKEN", "UNKNOWN", "GENESIS"]


class ChainStatusSummary(BaseModel):
    verified: int
    total: int
    integrity: Literal["OK", "BROKEN", "UNKNOWN"]


class StatsResponse(BaseModel):
    action_distribution: dict[str, int]
    threat_distribution: dict[str, int]
    chain_status: ChainStatusSummary
    period: dict[str, str]


class VerifyChainResponse(BaseModel):
    verified_count: int
    total_count: int
    first_break: dict[str, Any] | None
    integrity: Literal["OK", "BROKEN", "UNKNOWN"]


class SearchHitOut(BaseModel):
    event_id: int
    timestamp_iso: str
    action: str
    sig_valid: bool | None
    snippet: str
