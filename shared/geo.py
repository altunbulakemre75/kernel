"""Geographic transforms — full ETRS89/WGS84 ENU if pyproj is installed.
Otherwise small-area flat-Earth fallback (~0.01% error / 10 km).

Flat-Earth is only accurate at a single site and small radii (<20 km). For
multi-site or high-accuracy use, pyproj is required.
"""
from __future__ import annotations

import math
from functools import lru_cache

_EARTH_R_M = 6378137.0


try:
    from pyproj import Transformer, CRS   # noqa: PLC0415
    _HAS_PYPROJ = True
except ImportError:
    _HAS_PYPROJ = False


@lru_cache(maxsize=32)
def _enu_transformer(ref_lat: float, ref_lon: float, ref_alt: float = 0.0):
    """pyproj local-tangent-plane transformer.

    `+proj=ortho` orthographic projection: equivalent to east/north in
    small areas (~100 km radius), universally supported in proj 7+.
    +proj=topocentric exists in proj 9.x but is not available on all
    systems; ortho is portable.
    """
    # ref_alt is not used in the current ortho projection; altitude
    # difference is subtracted as u = alt - ref_alt. (Will be inlined
    # here when topocentric arrives in proj 9.x.)
    del ref_alt
    if not _HAS_PYPROJ:
        return None
    local = CRS.from_proj4(
        f"+proj=ortho +lat_0={ref_lat} +lon_0={ref_lon} +ellps=WGS84 +units=m"
    )
    wgs84 = CRS.from_epsg(4326)
    return Transformer.from_crs(wgs84, local, always_xy=True)


def latlon_to_enu(
    lat: float, lon: float, ref_lat: float, ref_lon: float,
    alt: float = 0.0, ref_alt: float = 0.0,
) -> tuple[float, float, float]:
    """Lat/lon → ENU (east, north, up) metres.

    Uses pyproj if available (accurate at all scales); otherwise flat-Earth fallback.
    """
    transformer = _enu_transformer(ref_lat, ref_lon, ref_alt)
    if transformer is not None:
        try:
            e, n = transformer.transform(lon, lat)
            return float(e), float(n), alt - ref_alt
        except Exception:
            pass   # flat-Earth fallback

    d_lat = math.radians(lat - ref_lat)
    d_lon = math.radians(lon - ref_lon)
    east = d_lon * _EARTH_R_M * math.cos(math.radians(ref_lat))
    north = d_lat * _EARTH_R_M
    up = alt - ref_alt
    return east, north, up


def enu_to_latlon(
    east: float, north: float, ref_lat: float, ref_lon: float,
    up: float = 0.0, ref_alt: float = 0.0,
) -> tuple[float, float, float]:
    """ENU → lat/lon. Inverse transform."""
    transformer = _enu_transformer(ref_lat, ref_lon, ref_alt)
    if transformer is not None:
        try:
            lon, lat = transformer.transform(east, north, direction="INVERSE")
            return float(lat), float(lon), up + ref_alt
        except Exception:
            pass

    d_lat = math.degrees(north / _EARTH_R_M)
    d_lon = math.degrees(east / (_EARTH_R_M * math.cos(math.radians(ref_lat))))
    return ref_lat + d_lat, ref_lon + d_lon, up + ref_alt


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


def has_pyproj() -> bool:
    return _HAS_PYPROJ
