from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from canari.models import AlertEvent
from canari.registry import CanaryRegistry


class ForensicReporter:
    def __init__(self, registry: CanaryRegistry):
        self.registry = registry

    def incident_report(self, incident_id: str) -> dict:
        alerts = self.registry.list_alerts(limit=1000, incident_id=incident_id)
        if not alerts:
            return {
                "incident_id": incident_id,
                "found": False,
                "event_count": 0,
                "timeline": [],
            }

        alerts = sorted(alerts, key=lambda a: a.triggered_at)
        first = alerts[0]
        last = alerts[-1]
        severity = max(alerts, key=lambda a: _severity_rank(a.severity.value)).severity.value

        return {
            "incident_id": incident_id,
            "found": True,
            "conversation_id": first.conversation_id,
            "event_count": len(alerts),
            "first_seen": _to_z(first.triggered_at),
            "last_seen": _to_z(last.triggered_at),
            "duration_seconds": int((last.triggered_at - first.triggered_at).total_seconds()),
            "max_severity": severity,
            "surfaces": sorted({a.detection_surface for a in alerts}),
            "tokens": sorted({a.canary_id for a in alerts}),
            "timeline": [
                {
                    "triggered_at": _to_z(a.triggered_at),
                    "severity": a.severity.value,
                    "surface": a.detection_surface,
                    "canary_id": a.canary_id,
                    "snippet": a.output_snippet,
                }
                for a in alerts
            ],
        }

    def forensic_summary(self, limit: int = 5000, tenant_id: str | None = None) -> dict:
        alerts = self.registry.list_alerts(limit=limit, tenant_id=tenant_id)
        token_stats = self.registry.stats() if tenant_id is None else {"tenant_scoped": True}
        alert_stats = self.registry.alert_stats(tenant_id=tenant_id)

        if not alerts:
            return {
                "timeframe": {"first_seen": None, "last_seen": None},
                "tokens": token_stats,
                "alerts": alert_stats,
                "top_incidents": [],
            }

        alerts_sorted = sorted(alerts, key=lambda a: a.triggered_at)
        incidents = Counter(a.incident_id for a in alerts if a.incident_id)
        top_incidents = [
            {"incident_id": incident_id, "event_count": count}
            for incident_id, count in incidents.most_common(5)
        ]

        return {
            "timeframe": {
                "first_seen": _to_z(alerts_sorted[0].triggered_at),
                "last_seen": _to_z(alerts_sorted[-1].triggered_at),
            },
            "tokens": token_stats,
            "alerts": alert_stats,
            "top_incidents": top_incidents,
        }

    def siem_events(self, limit: int = 1000, tenant_id: str | None = None) -> list[dict]:
        alerts = self.registry.list_alerts(limit=limit, tenant_id=tenant_id)
        out = []
        for a in alerts:
            out.append(
                {
                    "ts": _to_z(a.triggered_at),
                    "source": "canari",
                    "event_type": "canary_leak",
                    "severity": a.severity.value,
                    "detection_surface": a.detection_surface,
                    "incident_id": a.incident_id,
                    "conversation_id": a.conversation_id,
                    "tenant_id": a.tenant_id,
                    "canary_id": a.canary_id,
                    "token_type": a.token_type.value,
                    "snippet": a.output_snippet,
                    "correlation_count": a.correlation_count,
                }
            )
        return out


def _to_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _severity_rank(severity: str) -> int:
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    return order.get(severity, -1)
