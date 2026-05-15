"""Data association — Hungarian + Mahalanobis gate.

Matches tracks to measurements with minimum total cost.
Pairs outside the gate (Mahalanobis > threshold) are left unassigned.
"""
from __future__ import annotations

import numpy as np
from scipy.optimize import linear_sum_assignment

from services.fusion.kf_engine import mahalanobis_distance


# 99.7% gate for 3-DOF measurements (chi-square, df=3) ≈ sqrt(14.16)
DEFAULT_GATE = 3.77
UNASSIGNED = -1


def associate(
    tracks: list,  # KalmanFilter list
    measurements: list[np.ndarray],
    gate: float = DEFAULT_GATE,
) -> tuple[list[tuple[int, int]], list[int], list[int]]:
    """Match tracks to measurements by Mahalanobis distance.

    Returns:
        matches: (track_idx, meas_idx) matched pairs
        unmatched_tracks: indices of unmatched tracks
        unmatched_meas: indices of unmatched measurements
    """
    n_tracks, n_meas = len(tracks), len(measurements)
    if n_tracks == 0 or n_meas == 0:
        return [], list(range(n_tracks)), list(range(n_meas))

    LARGE = 1e6
    cost = np.full((n_tracks, n_meas), LARGE)
    for i, kf in enumerate(tracks):
        for j, z in enumerate(measurements):
            d = mahalanobis_distance(kf, z)
            if d <= gate:
                cost[i, j] = d

    row_ind, col_ind = linear_sum_assignment(cost)

    matches: list[tuple[int, int]] = []
    matched_tracks: set[int] = set()
    matched_meas: set[int] = set()
    for r, c in zip(row_ind, col_ind):
        if cost[r, c] < LARGE:
            matches.append((int(r), int(c)))
            matched_tracks.add(int(r))
            matched_meas.add(int(c))

    unmatched_tracks = [i for i in range(n_tracks) if i not in matched_tracks]
    unmatched_meas = [j for j in range(n_meas) if j not in matched_meas]
    return matches, unmatched_tracks, unmatched_meas
