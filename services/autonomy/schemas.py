"""Autonomous intercept schemas."""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class InterceptPhase(str, Enum):
    IDLE = "idle"
    APPROACH = "approach"       # approach the target track
    SHADOW = "shadow"           # close-follow the target
    ABORT = "abort"             # mission abort
    RTB = "rtb"                 # return-to-base


class Waypoint(BaseModel):
    """WGS84 waypoint."""
    latitude: float
    longitude: float
    altitude_m: float = 100.0
    speed_mps: float | None = None


class InterceptCommand(BaseModel):
    """Command to be sent to an intercept drone."""
    target_track_id: str
    phase: InterceptPhase
    waypoint: Waypoint
    max_approach_distance_m: float = Field(ge=10.0, default=100.0)
    operator_approved: bool  # always mandatory
    approved_by: str | None = None
    approved_at_iso: str | None = None


class InterceptState(BaseModel):
    """Current state of the intercept drone."""
    drone_id: str
    phase: InterceptPhase
    current_wp: Waypoint | None = None
    target_track_id: str | None = None
    target_distance_m: float | None = None
