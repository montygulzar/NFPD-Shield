"""In-process counters surfaced through ``/shield status`` and ``/shield health``.

Deliberately dependency-free: no Prometheus client is required to deploy. The
counter snapshot is JSON serialisable so an operator can scrape it from logs or
extend :func:`snapshot` into an exporter later.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Any


class Metrics:
    """Thread-safe counters, gauges and simple duration histograms."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, float] = defaultdict(float)
        self._gauges: dict[str, float] = {}
        self._durations: dict[str, list[float]] = defaultdict(list)
        self._started_at = time.time()

    def incr(self, name: str, value: float = 1.0, **labels: Any) -> None:
        with self._lock:
            self._counters[_key(name, labels)] += value

    def gauge(self, name: str, value: float, **labels: Any) -> None:
        with self._lock:
            self._gauges[_key(name, labels)] = value

    def observe(self, name: str, seconds: float, **labels: Any) -> None:
        with self._lock:
            bucket = self._durations[_key(name, labels)]
            bucket.append(seconds)
            if len(bucket) > 512:
                del bucket[: len(bucket) - 512]

    def counter_value(self, name: str, **labels: Any) -> float:
        with self._lock:
            return self._counters.get(_key(name, labels), 0.0)

    def uptime_seconds(self) -> float:
        return time.time() - self._started_at

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            durations = {
                key: {
                    "count": len(values),
                    "avg": round(sum(values) / len(values), 4),
                    "max": round(max(values), 4),
                }
                for key, values in self._durations.items()
                if values
            }
            return {
                "uptime_seconds": round(self.uptime_seconds(), 1),
                "counters": dict(sorted(self._counters.items())),
                "gauges": dict(sorted(self._gauges.items())),
                "durations": durations,
            }

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._durations.clear()


def _key(name: str, labels: dict[str, Any]) -> str:
    if not labels:
        return name
    rendered = ",".join(f"{k}={labels[k]}" for k in sorted(labels))
    return f"{name}{{{rendered}}}"


#: Process-wide metrics registry.
METRICS = Metrics()
