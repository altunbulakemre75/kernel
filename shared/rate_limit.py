"""Per-sensor rate limit + queue-depth circuit breaker.

DoS defence: even if a sensor sends 10k messages per second, it will
not bloat the fusion queue. Two layers:
  1. SlidingWindowLimiter — per-sensor max events/sec
  2. CircuitBreaker — drop when downstream queue > threshold

Both paths are idempotent, thread-safe (asyncio lock), and emit
Prometheus metrics.
"""
from __future__ import annotations

import asyncio
import time
from collections import deque

from prometheus_client import Counter, Gauge

_rate_dropped = Counter(
    "kernel_rate_limit_dropped_total",
    "Messages dropped by rate limit or circuit breaker",
    ["sensor_id", "reason"],
)
_queue_depth = Gauge(
    "kernel_queue_depth_ratio",
    "Downstream queue fill ratio (0..1)",
    ["component"],
)


class SlidingWindowLimiter:
    """Drop if the event count for a sensor_id in the last N seconds >= max_events."""

    def __init__(self, max_events_per_sec: int = 100, window_s: float = 1.0) -> None:
        self.max_events = max_events_per_sec
        self.window_s = window_s
        self._timestamps: dict[str, deque[float]] = {}
        self._lock = asyncio.Lock()

    async def allow(self, sensor_id: str) -> bool:
        """True → accept, False → drop (metric counter incremented)."""
        now = time.monotonic()
        cutoff = now - self.window_s
        async with self._lock:
            times = self._timestamps.setdefault(sensor_id, deque())
            while times and times[0] < cutoff:
                times.popleft()
            if len(times) >= self.max_events:
                _rate_dropped.labels(sensor_id=sensor_id, reason="rate_limit").inc()
                return False
            times.append(now)
            return True

    def current_rate(self, sensor_id: str) -> int:
        return len(self._timestamps.get(sensor_id, deque()))


class QueueCircuitBreaker:
    """Drop low-priority events when the queue exceeds a fill threshold.

    threshold=0.8 → dropping starts at 80% queue fill, emergency mode at 95%.
    Same rule for every sensor; sensor_priority to be added later.
    """

    def __init__(
        self, queue: asyncio.Queue, component_name: str,
        soft_threshold: float = 0.80, hard_threshold: float = 0.95,
    ) -> None:
        self.queue = queue
        self.component = component_name
        self.soft = soft_threshold
        self.hard = hard_threshold

    def _depth_ratio(self) -> float:
        maxsize = self.queue.maxsize or 1
        ratio = self.queue.qsize() / maxsize
        _queue_depth.labels(component=self.component).set(ratio)
        return ratio

    def allow(self, sensor_id: str, is_critical: bool = False) -> bool:
        """If is_critical=True, use the hard threshold; otherwise use soft."""
        ratio = self._depth_ratio()
        if ratio >= self.hard:
            _rate_dropped.labels(sensor_id=sensor_id, reason="hard_breaker").inc()
            return False
        if ratio >= self.soft and not is_critical:
            _rate_dropped.labels(sensor_id=sensor_id, reason="soft_breaker").inc()
            return False
        return True
