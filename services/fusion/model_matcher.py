"""Entity model classification — in-memory vector lookup.

Performs nearest-neighbor matching of sensor-derived feature vectors against
a catalog of known entity signatures. Used by the fusion layer to attach
a likely model/type label to a track without requiring a heavyweight
classifier in the hot path.

The catalog format (`services/fusion/drone_catalog.json`) is domain-neutral
— it stores `{model_name, manufacturer, embedding[16]}` records. The name
reflects the original deployment context (UAS tracking) but the matcher
itself is type-agnostic; any entity catalog with the same schema works
(vehicle types, vessel classes, etc.).

Two backend paths:
  1. FAISS available  → IndexFlatL2 (fast for 10k+ entries)
  2. FAISS unavailable → numpy argmin (sufficient for small catalogs,
                                      no install dependency)

Embedding source in production: YOLO feature extractor output, or
ODID manufacturer + UA_type lookup.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

CATALOG_PATH = Path(__file__).parent / "drone_catalog.json"


class DroneCatalog:
    """Drone model lookup — both FAISS and numpy fallback."""

    def __init__(self, catalog_path: Path | None = None) -> None:
        path = catalog_path or CATALOG_PATH
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
        else:
            data = []
        self._entries = data
        if not data:
            self._vectors = np.zeros((0, 16), dtype=np.float32)
        else:
            self._vectors = np.array([e["embedding"] for e in data], dtype=np.float32)
        self._index = self._build_index()

    def _build_index(self):
        if len(self._entries) == 0:
            return None
        try:
            import faiss  # noqa: PLC0415

            d = self._vectors.shape[1]
            idx = faiss.IndexFlatL2(d)
            idx.add(self._vectors)
            return idx
        except ImportError:
            return None  # numpy fallback

    def query(self, embedding: list[float] | np.ndarray, threshold: float = 0.5) -> dict | None:
        """Search for the nearest drone model.

        Args:
            embedding: query vector (16-dim)
            threshold: maximum L2 distance (0..inf, smaller is better)

        Returns:
            {model_name, manufacturer, distance} or None
        """
        if len(self._entries) == 0:
            return None
        vec = np.asarray(embedding, dtype=np.float32).reshape(1, -1)
        if vec.shape[1] != self._vectors.shape[1]:
            raise ValueError(
                f"Embedding dimension mismatch: {vec.shape[1]} vs {self._vectors.shape[1]}"
            )

        if self._index is not None:
            distances, indices = self._index.search(vec, 1)
            best_idx = int(indices[0, 0])
            dist = float(distances[0, 0])
        else:
            dists_sq = np.sum((self._vectors - vec) ** 2, axis=1)
            best_idx = int(np.argmin(dists_sq))
            dist = float(np.sqrt(dists_sq[best_idx]))

        if dist > threshold:
            return None

        entry = self._entries[best_idx]
        return {
            "model_name": entry["model_name"],
            "manufacturer": entry["manufacturer"],
            "distance": dist,
        }
