"""Track and Measurement schemas — for the fusion layer."""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class TrackState(str, Enum):
    TENTATIVE = "tentative"   # new detection, not yet confirmed
    CONFIRMED = "confirmed"   # confirmed by N consecutive detections
    LOST = "lost"             # M consecutive misses (but not deleted)
    DELETED = "deleted"       # removed from the system


class SensorType(str, Enum):
    CAMERA = "camera"
    RF_ODID = "rf_odid"
    RF_WIFI = "rf_wifi"
    RADAR = "radar"
    AIS = "ais"


class Measurement(BaseModel):
    """Single sensor measurement — input to the fusion engine."""
    sensor_id: str
    sensor_type: SensorType
    timestamp_iso: str
    # 3D position (ENU metres) or lat/lon/alt — varies by sensor
    x: float
    y: float
    z: float = 0.0
    # Measurement noise (1-sigma in metres)
    sigma_x: float = 5.0
    sigma_y: float = 5.0
    sigma_z: float = 10.0
    # Optional meta
    class_name: str | None = None
    class_conf: float | None = None
    uas_id: str | None = None  # if ODID is present
    rssi_dbm: float | None = None


class Track(BaseModel):
    """Fused track produced by the fusion engine.

    NATS subject: nizam.tracks.active
    """
    track_id: str
    state: TrackState
    # Kalman state: [x, y, z, vx, vy, vz] (ENU metres, m/s)
    x: float
    y: float
    z: float
    vx: float
    vy: float
    vz: float
    # Covariance diagonal (position 1-sigma, metres)
    sigma_x: float
    sigma_y: float
    sigma_z: float
    # Meta
    last_update_iso: str
    hits: int = Field(ge=0, description="Total detection count")
    misses: int = Field(ge=0, description="Consecutive missed ticks")
    sources: list[SensorType] = Field(default_factory=list)
    uas_id: str | None = None
    class_name: str | None = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
