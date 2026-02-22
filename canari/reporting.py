from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from canari.models import AlertEvent
from canari.registry import CanaryRegistry


class ForensicReporter:
    def __init__(self, registry: CanaryRegistry):
        self.registry = registry

    def incident_report(
        self,
        incident_id: str,
        *,
        tenant_id: str | None = None,
        application_id: str | None = None,
    ) -> dict:
        alerts = self.registry.list_alerts(
            limit=1000,
            incident_id=incident_id,
            tenant_id=tenant_id,
            application_id=application_id,
        )
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

    def forensic_summary(
        self,
        limit: int = 5000,
        tenant_id: str | None = None,
        application_id: str | None = None,
    ) -> dict:
        alerts = self.registry.list_alerts(limit=limit, tenant_id=tenant_id, application_id=application_id)
        token_stats = self.registry.stats() if tenant_id is None else {"tenant_scoped": True}
        alert_stats = self.registry.alert_stats(tenant_id=tenant_id, application_id=application_id)

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

    def siem_events(
        self,
        limit: int = 1000,
        tenant_id: str | None = None,
        application_id: str | None = None,
    ) -> list[dict]:
        alerts = self.registry.list_alerts(limit=limit, tenant_id=tenant_id, application_id=application_id)
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
                    "application_id": a.application_id,
                    "canary_id": a.canary_id,
                    "token_type": a.token_type.value,
                    "snippet": a.output_snippet,
                    "correlation_count": a.correlation_count,
                }
            )
        return out

    def siem_cef_events(
        self,
        limit: int = 1000,
        tenant_id: str | None = None,
        application_id: str | None = None,
    ) -> list[str]:
        rows = self.siem_events(limit=limit, tenant_id=tenant_id, application_id=application_id)
        out: list[str] = []
        for row in rows:
            # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
            sev = {"low": 2, "medium": 5, "high": 8, "critical": 10}.get(row.get("severity", "low"), 1)
            sig_id = row.get("token_type", "unknown")
            name = "canary_leak_detected"
            ext_parts = [
                f"rt={row.get('ts', '')}",
                f"cs1Label=incident_id cs1={row.get('incident_id', '') or ''}",
                f"cs2Label=conversation_id cs2={row.get('conversation_id', '') or ''}",
                f"cs3Label=tenant_id cs3={row.get('tenant_id', '') or ''}",
                f"cs4Label=application_id cs4={row.get('application_id', '') or ''}",
                f"cs5Label=detection_surface cs5={row.get('detection_surface', '') or ''}",
                f"cn1Label=correlation_count cn1={row.get('correlation_count', 1)}",
            ]
            out.append(
                "CEF:0|Canari|IDS|0.1.0|"
                f"{sig_id}|{name}|{sev}|{' '.join(ext_parts)}"
            )
        return out

    def compliance_evidence_pack(
        self,
        *,
        limit: int = 5000,
        tenant_id: str | None = None,
        application_id: str | None = None,
    ) -> dict:
        summary = self.forensic_summary(limit=limit, tenant_id=tenant_id, application_id=application_id)
        alerts = self.registry.list_alerts(
            limit=min(limit, 5000),
            tenant_id=tenant_id,
            application_id=application_id,
        )
        incidents = {}
        for a in alerts:
            if a.incident_id:
                incidents[a.incident_id] = incidents.get(a.incident_id, 0) + 1
        audit_tail = self.registry.list_audit(limit=200, offset=0)
        recent_policy_actions = [
            row for row in audit_tail if row["action"] in {"persist_policy", "policy_set_api", "set_scoped_retention_policy"}
        ][:20]
        recent_key_actions = [
            row for row in audit_tail if row["action"] in {"create_api_key", "revoke_api_key", "rotate_api_key"}
        ][:20]

        return {
            "evidence_version": "v1",
            "schema_version": 1,
            "scope": {"tenant_id": tenant_id, "application_id": application_id},
            "summary": summary,
            "controls": {
                "policy_settings": self.registry.settings(),
                "retention_policies": self.registry.list_retention_policies(),
                "api_keys_metadata": self.registry.list_api_keys(include_inactive=True),
            },
            "operations": {
                "audit_recent_policy_actions": recent_policy_actions,
                "audit_recent_api_key_actions": recent_key_actions,
                "incident_count": len(incidents),
                "top_incidents": sorted(
                    [{"incident_id": k, "event_count": v} for k, v in incidents.items()],
                    key=lambda r: r["event_count"],
                    reverse=True,
                )[:10],
            },
            "siem_samples": {
                "json_events": self.siem_events(
                    limit=min(100, max(1, limit)),
                    tenant_id=tenant_id,
                    application_id=application_id,
                ),
                "cef_events": self.siem_cef_events(
                    limit=min(100, max(1, limit)),
                    tenant_id=tenant_id,
                    application_id=application_id,
                ),
            },
        }

    def incident_dossier(
        self,
        incident_id: str,
        *,
        tenant_id: str | None = None,
        application_id: str | None = None,
    ) -> dict:
        report = self.incident_report(
            incident_id,
            tenant_id=tenant_id,
            application_id=application_id,
        )
        if not report.get("found"):
            return {
                "dossier_version": "v1",
                "incident_id": incident_id,
                "found": False,
                "scope": {"tenant_id": tenant_id, "application_id": application_id},
                "incident": report,
            }

        incident_events = self.registry.list_alerts(
            limit=5000,
            incident_id=incident_id,
            tenant_id=tenant_id,
            application_id=application_id,
        )
        by_severity: dict[str, int] = {}
        by_surface: dict[str, int] = {}
        by_token: dict[str, int] = {}
        for a in incident_events:
            by_severity[a.severity.value] = by_severity.get(a.severity.value, 0) + 1
            by_surface[a.detection_surface] = by_surface.get(a.detection_surface, 0) + 1
            by_token[a.token_type.value] = by_token.get(a.token_type.value, 0) + 1

        audit_recent = self.registry.list_audit(limit=500, offset=0)
        policy_actions = [
            row for row in audit_recent if row["action"] in {"persist_policy", "policy_set_api", "set_scoped_retention_policy"}
        ][:25]
        response_actions = [
            row
            for row in audit_recent
            if row["action"] in {"rotate_canaries", "purge_alerts", "apply_retention_policy", "apply_scoped_retention_policies"}
        ][:25]

        return {
            "dossier_version": "v1",
            "incident_id": incident_id,
            "found": True,
            "scope": {"tenant_id": tenant_id, "application_id": application_id},
            "incident": report,
            "impact_summary": {
                "event_count": len(incident_events),
                "by_severity": by_severity,
                "by_surface": by_surface,
                "by_token_type": by_token,
            },
            "control_snapshot": {
                "settings": self.registry.settings(),
                "retention_policies": self.registry.list_retention_policies(),
            },
            "response_audit": {
                "policy_actions": policy_actions,
                "response_actions": response_actions,
            },
            "siem_extracts": {
                "json_events": self.siem_events(
                    limit=250,
                    tenant_id=tenant_id,
                    application_id=application_id,
                ),
                "cef_events": self.siem_cef_events(
                    limit=250,
                    tenant_id=tenant_id,
                    application_id=application_id,
                ),
            },
        }


def _to_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _severity_rank(severity: str) -> int:
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    return order.get(severity, -1)
