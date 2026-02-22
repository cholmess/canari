from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta, timezone

from canari.models import AlertEvent


class AlertRateLimiter:
    def __init__(self, window_seconds: int = 60, max_dispatches: int = 3):
        self.window = timedelta(seconds=max(1, window_seconds))
        self.max_dispatches = max(1, max_dispatches)
        self._history: dict[str, deque[datetime]] = {}

    def should_dispatch(self, event: AlertEvent) -> bool:
        now = event.triggered_at.astimezone(timezone.utc)
        key = f"{event.canary_id}:{event.detection_surface}"
        q = self._history.setdefault(key, deque())

        while q and now - q[0] > self.window:
            q.popleft()

        if len(q) >= self.max_dispatches:
            return False

        q.append(now)
        return True
