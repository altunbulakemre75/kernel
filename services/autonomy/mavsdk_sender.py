"""MAVSDK bridge — InterceptCommand → PX4 offboard.

Note: This is a pre-production shell. Real hardware/SITL testing
requires MAVSDK, PX4 SITL (Gazebo), and safety fences.
The mavsdk Python package is imported optionally — if absent, mock mode.
"""
from __future__ import annotations

import logging

from services.autonomy.schemas import InterceptCommand, InterceptPhase

log = logging.getLogger(__name__)


class MAVSDKSender:
    """Sends MAVSDK offboard commands to a PX4 drone.

    Usage:
        sender = MAVSDKSender("udp://:14540")
        await sender.connect()
        await sender.dispatch(intercept_command)
    """

    def __init__(self, connection_url: str = "udp://:14540") -> None:
        self.connection_url = connection_url
        self._drone = None  # mavsdk.System lazy init

    async def connect(self) -> None:
        try:
            from mavsdk import System
        except ImportError:
            log.warning("mavsdk not installed — running in mock mode")
            self._drone = "mock"
            return
        self._drone = System()
        await self._drone.connect(system_address=self.connection_url)

    async def dispatch(self, cmd: InterceptCommand) -> None:
        """Dispatch an InterceptCommand to the drone. Operator approval is mandatory."""
        if not cmd.operator_approved:
            raise RuntimeError("dispatch blocked: operator_approved=False")

        if self._drone == "mock" or self._drone is None:
            log.info(
                "MOCK MAVSDK dispatch: target=%s phase=%s wp=(%.6f,%.6f,%.1f)",
                cmd.target_track_id, cmd.phase.value,
                cmd.waypoint.latitude, cmd.waypoint.longitude, cmd.waypoint.altitude_m,
            )
            return

        # Real MAVSDK path — offboard position + arm
        from mavsdk.offboard import OffboardError, PositionNedYaw

        if cmd.phase == InterceptPhase.ABORT or cmd.phase == InterceptPhase.RTB:
            await self._drone.action.return_to_launch()
            return

        await self._drone.action.arm()
        try:
            await self._drone.offboard.set_position_ned(
                PositionNedYaw(0.0, 0.0, -cmd.waypoint.altitude_m, 0.0)
            )
            await self._drone.offboard.start()
        except OffboardError as exc:
            log.error("offboard error: %s", exc)
            raise

    async def close(self) -> None:
        if self._drone and self._drone != "mock":
            # MAVSDK System object does not require explicit close
            pass
