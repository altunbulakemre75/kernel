"""Geofence — prevent violations of friendly zones and civilian areas.

Every intercept command waypoint is verified to not intersect with
prohibited zones. Prohibited zone = no-fly zone (civilian, friendly
base, airport...).
"""
from __future__ import annotations

import math

from pydantic import BaseModel

from services.autonomy.schemas import Waypoint


class NoFlyZone(BaseModel):
    """Circular no-fly zone (lat/lon centre + radius)."""
    zone_id: str
    name: str
    center_lat: float
    center_lon: float
    radius_m: float
    ceiling_m: float | None = None  # None = all altitudes


_EARTH_R_M = 6378137.0


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two points (metres)."""
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2))
        * math.sin(dlon / 2) ** 2
    )
    return 2 * _EARTH_R_M * math.asin(math.sqrt(max(0.0, a)))


def violates_geofence(wp: Waypoint, zones: list[NoFlyZone]) -> NoFlyZone | None:
    """If the waypoint enters any no-fly zone, return the first matching zone."""
    for zone in zones:
        dist = haversine_m(wp.latitude, wp.longitude, zone.center_lat, zone.center_lon)
        if dist > zone.radius_m:
            continue
        if zone.ceiling_m is not None and wp.altitude_m > zone.ceiling_m:
            continue
        return zone
    return None
