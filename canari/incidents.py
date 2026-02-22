from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from canari.models import AlertEvent, AlertSeverity


@dataclass
class IncidentSnapshot:
    incident_id: str
    conversation_id: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    surfaces: list[str]
    max_severity: str


class IncidentManager:
    def __init__(self, window_seconds: int = 600):
        self.window = timedelta(seconds=window_seconds)
        self._events: deque[AlertEvent] = deque(maxlen=5000)

    def correlate(self, event: AlertEvent) -> AlertEvent:
        now = event.triggered_at.astimezone(timezone.utc)
        self._trim(now)

        conv_id = event.conversation_id or "unknown"
        recent = [
            e
            for e in self._events
            if (e.conversation_id or "unknown") == conv_id and now - e.triggered_at.astimezone(timezone.utc) <= self.window
        ]
        surfaces = {e.detection_surface for e in recent}
        surfaces.add(event.detection_surface)

        correlation_count = len(recent) + 1
        incident_id = f"inc-{conv_id}-{int(now.timestamp()) // int(self.window.total_seconds())}"

        upgraded = event.model_copy(deep=True)
        upgraded.incident_id = incident_id
        upgraded.correlation_count = correlation_count

        if len(surfaces) >= 2 and correlation_count >= 2:
            upgraded.severity = AlertSeverity.CRITICAL
            upgraded.forensic_notes = (
                f"{upgraded.forensic_notes} Correlated multi-surface exfiltration sequence "
                f"({', '.join(sorted(surfaces))}) within {int(self.window.total_seconds())}s window."
            )
        elif correlation_count >= 3 and upgraded.severity != AlertSeverity.CRITICAL:
            upgraded.severity = AlertSeverity.CRITICAL
            upgraded.forensic_notes = (
                f"{upgraded.forensic_notes} Repeated leak pattern with {correlation_count} related events "
                f"in {int(self.window.total_seconds())}s window."
            )

        self._events.append(upgraded)
        return upgraded

    def recent_incidents(self, limit: int = 50) -> list[IncidentSnapshot]:
        if limit <= 0:
            return []

        grouped: dict[str, list[AlertEvent]] = {}
        for event in self._events:
            if not event.incident_id:
                continue
            grouped.setdefault(event.incident_id, []).append(event)

        snapshots: list[IncidentSnapshot] = []
        for incident_id, events in grouped.items():
            events_sorted = sorted(events, key=lambda e: e.triggered_at)
            conv = events_sorted[0].conversation_id or "unknown"
            max_severity = max(events_sorted, key=lambda e: _severity_rank(e.severity)).severity.value
            snapshots.append(
                IncidentSnapshot(
                    incident_id=incident_id,
                    conversation_id=conv,
                    first_seen=events_sorted[0].triggered_at,
                    last_seen=events_sorted[-1].triggered_at,
                    event_count=len(events_sorted),
                    surfaces=sorted({e.detection_surface for e in events_sorted}),
                    max_severity=max_severity,
                )
            )

        snapshots.sort(key=lambda s: s.last_seen, reverse=True)
        return snapshots[:limit]

    def _trim(self, now: datetime) -> None:
        while self._events:
            oldest = self._events[0]
            if now - oldest.triggered_at.astimezone(timezone.utc) > self.window:
                self._events.popleft()
            else:
                break


def _severity_rank(severity: AlertSeverity) -> int:
    order = {
        AlertSeverity.LOW: 0,
        AlertSeverity.MEDIUM: 1,
        AlertSeverity.HIGH: 2,
        AlertSeverity.CRITICAL: 3,
    }
    return order[severity]
