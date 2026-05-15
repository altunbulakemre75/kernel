"""IMM (Interacting Multiple Model) filter — better for manoeuvring states.

Three models run in parallel:
  - CV (constant velocity) — straight-line flight
  - CA (constant acceleration) — dive/climb
  - CT (coordinated turn) — constant-rate turn

At each tick the most probable model is selected; track KF state follows.
Corresponds to the "filterpy.IMMEstimator" line in the plan.
"""
from __future__ import annotations

import numpy as np
from filterpy.kalman import IMMEstimator, KalmanFilter

from services.fusion.kf_engine import make_cv_filter


def _make_ca_filter(x0: float, y0: float, z0: float, sigma_pos: float = 10.0) -> KalmanFilter:
    """Constant acceleration: state = [x, y, z, vx, vy, vz, ax, ay, az]."""
    kf = KalmanFilter(dim_x=9, dim_z=3)
    kf.x = np.array([x0, y0, z0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0])
    kf.P = np.diag([sigma_pos**2] * 3 + [50.0**2] * 3 + [5.0**2] * 3)
    kf.H = np.zeros((3, 9))
    kf.H[0, 0] = kf.H[1, 1] = kf.H[2, 2] = 1.0
    kf.R = np.eye(3) * (sigma_pos**2)
    kf._dt = 0.1  # type: ignore[attr-defined]
    _set_ca_matrices(kf, 0.1)
    return kf


def _set_ca_matrices(kf: KalmanFilter, dt: float) -> None:
    """Update F and Q (CA model) matrices for the given dt."""
    F = np.eye(9)
    for i in range(3):
        F[i, i + 3] = dt
        F[i, i + 6] = 0.5 * dt * dt
        F[i + 3, i + 6] = dt
    kf.F = F
    q = 1.0  # acceleration variance
    Q = np.eye(9) * q
    kf.Q = Q


def make_imm_filter(
    x0: float, y0: float, z0: float, sigma_pos: float = 10.0
) -> IMMEstimator:
    """CV + CA two-model IMM filter (CT optional, can be added after testing).

    filterpy.IMMEstimator requires the same state dimension — projecting
    CA's 9-dim state to CV's 6-dim requires a simple projection. This
    implementation uses two CV filters at different process noise levels
    (pragmatic approach):
      - Filter 1: low noise (straight-line flight)
      - Filter 2: high noise (manoeuvre)
    """
    kf_cv = make_cv_filter(x0, y0, z0, sigma_pos=sigma_pos, process_noise=0.5)
    kf_maneuver = make_cv_filter(x0, y0, z0, sigma_pos=sigma_pos, process_noise=5.0)

    # Mode probabilities (straight-line flight prioritised initially)
    mu = np.array([0.9, 0.1])
    # Transition matrix (0.95 stay probability, 0.05 mode switch)
    trans_mat = np.array([[0.95, 0.05], [0.05, 0.95]])

    imm = IMMEstimator(filters=[kf_cv, kf_maneuver], mu=mu, M=trans_mat)
    return imm


def imm_mode_probabilities(imm: IMMEstimator) -> list[float]:
    """Instantaneous probability of each mode (0..1)."""
    return [float(m) for m in imm.mu]
