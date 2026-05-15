"""Camera calibration system — sensor_id → (lat, lon, alt, heading, fov, intrinsics).

YAML-based single source of truth (config/cameras/*.yaml). Each camera:
  - location: lat/lon/alt + heading (degrees clockwise from true north)
  - intrinsics: focal length, principal point, distortion (optional)
  - fov_h/fov_v: horizontal/vertical field of view (degrees)

Production: each camera is calibrated with OpenCV `cv2.calibrateCamera`
using a chessboard pattern during initial setup, and the result is written
to YAML. During field deployment, GPS + compass provide location + heading.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path

import yaml


CONFIG_DIR = Path("config/cameras")


@dataclass
class CameraCalibration:
    sensor_id: str
    # Position (WGS84)
    latitude: float
    longitude: float
    altitude_m: float = 0.0
    heading_deg: float = 0.0       # true north clockwise (0=N, 90=E)
    # Field of view (approximate)
    fov_h_deg: float = 60.0
    fov_v_deg: float = 40.0
    # Default target range (when triangulation is not possible)
    nominal_range_m: float = 250.0
    # Intrinsics (optional, may be None — nominal_range fallback)
    focal_length_px: float | None = None
    principal_cx: float | None = None
    principal_cy: float | None = None


def load_calibration(sensor_id: str, config_dir: Path | None = None) -> CameraCalibration:
    """Load camera calibration from YAML. Falls back to Ankara default if not found."""
    cdir = config_dir or CONFIG_DIR
    path = cdir / f"{sensor_id}.yaml"
    if not path.exists():
        return _default(sensor_id)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return CameraCalibration(
        sensor_id=sensor_id,
        latitude=float(data["latitude"]),
        longitude=float(data["longitude"]),
        altitude_m=float(data.get("altitude_m", 0.0)),
        heading_deg=float(data.get("heading_deg", 0.0)),
        fov_h_deg=float(data.get("fov_h_deg", 60.0)),
        fov_v_deg=float(data.get("fov_v_deg", 40.0)),
        nominal_range_m=float(data.get("nominal_range_m", 250.0)),
        focal_length_px=data.get("focal_length_px"),
        principal_cx=data.get("principal_cx"),
        principal_cy=data.get("principal_cy"),
    )


def _default(sensor_id: str) -> CameraCalibration:
    """Dev default: a north-facing camera at Ankara centre."""
    return CameraCalibration(
        sensor_id=sensor_id,
        latitude=39.9334, longitude=32.8597, altitude_m=900.0,
        heading_deg=0.0, fov_h_deg=60.0, fov_v_deg=40.0,
        nominal_range_m=250.0,
    )


def bbox_center_to_bearing(
    cx_norm: float,  # 0..1, bbox x centre / frame width
    cy_norm: float,  # 0..1
    calibration: CameraCalibration,
) -> tuple[float, float]:
    """Convert bbox centre to bearing + elevation from the camera (degrees).

    Simple pinhole assumption: principal point at frame centre, FOV
    symmetric around the camera heading.
    """
    # cx_norm=0.5 → bearing = heading (dead centre)
    # cx_norm=1.0 → bearing = heading + fov_h/2 (right)
    bearing = calibration.heading_deg + (cx_norm - 0.5) * calibration.fov_h_deg
    bearing = bearing % 360.0
    # cy_norm=0.5 → elevation = 0 (horizon)
    # cy_norm=0.0 → elevation = +fov_v/2 (up)
    elevation = (0.5 - cy_norm) * calibration.fov_v_deg
    return bearing, elevation


def project_bbox_to_position(
    bbox_x1: float, bbox_y1: float, bbox_x2: float, bbox_y2: float,
    frame_w: int, frame_h: int,
    calibration: CameraCalibration,
    range_m: float | None = None,
) -> tuple[float, float, float]:
    """bbox → (lat, lon, alt) projection.

    If range_m is not provided, calibration.nominal_range_m is used.
    Production: DEM + LOS intersection or stereo camera triangulation.
    """
    cx = 0.5 * (bbox_x1 + bbox_x2) / frame_w
    cy = 0.5 * (bbox_y1 + bbox_y2) / frame_h
    bearing_deg, elevation_deg = bbox_center_to_bearing(cx, cy, calibration)

    r = range_m if range_m is not None else calibration.nominal_range_m
    # Small-area flat-Earth
    bearing_rad = math.radians(bearing_deg)
    east = r * math.sin(bearing_rad)
    north = r * math.cos(bearing_rad)

    _EARTH_R = 6378137.0
    d_lat = math.degrees(north / _EARTH_R)
    d_lon = math.degrees(east / (_EARTH_R * math.cos(math.radians(calibration.latitude))))

    lat = calibration.latitude + d_lat
    lon = calibration.longitude + d_lon
    alt = calibration.altitude_m + r * math.sin(math.radians(elevation_deg))
    return lat, lon, alt
