"""
Reference implementations for action sinks.

This module provides example downstream consumers of the `Decision` object
produced by `services/decision/`. It includes:

- `geofence.py` — Static no-fly-zone definitions and violation checks.
- `intercept_planner.py` — Waypoint planning for autonomous platforms
  capable of executing intercept maneuvers.
- `mavsdk_sender.py` — MAVSDK-based action dispatcher for PX4/ArduPilot
  vehicles.

These are illustrative integration targets. They are implemented and unit
tested, but are NOT integration tested against real hardware in this
repository, and they are NOT required for the core decision/audit
pipeline. Most users of kernel will not touch this module — the typical
deployment writes its own action sink (ROS2 publisher, custom HTTP
webhook, MQTT bridge) and consumes `Decision` objects directly.

If your use case does not involve autonomous platforms, you can safely
ignore this module entirely.
"""
