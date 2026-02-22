from __future__ import annotations

import csv
import json
from pathlib import Path

from canari.models import AlertEvent
from canari.registry import CanaryRegistry


class AlertExporter:
    def __init__(self, registry: CanaryRegistry):
        self.registry = registry

    def export_jsonl(
        self,
        path: str,
        *,
        limit: int = 1000,
        severity: str | None = None,
        detection_surface: str | None = None,
        conversation_id: str | None = None,
        incident_id: str | None = None,
        since: str | None = None,
        until: str | None = None,
        redact: bool = False,
        tenant_id: str | None = None,
    ) -> int:
        alerts = self.registry.list_alerts(
            limit=limit,
            severity=severity,
            detection_surface=detection_surface,
            conversation_id=conversation_id,
            incident_id=incident_id,
            since=since,
            until=until,
            tenant_id=tenant_id,
        )
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as f:
            for event in alerts:
                payload = _event_to_dict(event)
                if redact:
                    payload = _redact_payload(payload)
                f.write(json.dumps(payload, default=str) + "\n")
        return len(alerts)

    def export_csv(
        self,
        path: str,
        *,
        limit: int = 1000,
        severity: str | None = None,
        detection_surface: str | None = None,
        conversation_id: str | None = None,
        incident_id: str | None = None,
        since: str | None = None,
        until: str | None = None,
        redact: bool = False,
        tenant_id: str | None = None,
    ) -> int:
        alerts = self.registry.list_alerts(
            limit=limit,
            severity=severity,
            detection_surface=detection_surface,
            conversation_id=conversation_id,
            incident_id=incident_id,
            since=since,
            until=until,
            tenant_id=tenant_id,
        )
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)

        fieldnames = [
            "id",
            "canary_id",
            "canary_value",
            "token_type",
            "severity",
            "detection_surface",
            "conversation_id",
            "tenant_id",
            "incident_id",
            "correlation_count",
            "triggered_at",
            "injected_at",
            "injection_strategy",
            "injection_location",
            "output_snippet",
            "forensic_notes",
        ]
        with out.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for event in alerts:
                canary_value = event.canary_value if not redact else "[REDACTED]"
                snippet = event.output_snippet
                if redact:
                    snippet = (snippet or "").replace(event.canary_value, "[REDACTED]")
                writer.writerow(
                    {
                        "id": event.id,
                        "canary_id": event.canary_id,
                        "canary_value": canary_value,
                        "token_type": event.token_type.value,
                        "severity": event.severity.value,
                        "detection_surface": event.detection_surface,
                        "conversation_id": event.conversation_id,
                        "tenant_id": event.tenant_id,
                        "incident_id": event.incident_id,
                        "correlation_count": event.correlation_count,
                        "triggered_at": event.triggered_at.isoformat(),
                        "injected_at": event.injected_at.isoformat(),
                        "injection_strategy": event.injection_strategy.value,
                        "injection_location": event.injection_location,
                        "output_snippet": snippet,
                        "forensic_notes": event.forensic_notes,
                    }
                )
        return len(alerts)


def _event_to_dict(event: AlertEvent) -> dict:
    return {
        "id": event.id,
        "canary_id": event.canary_id,
        "canary_value": event.canary_value,
        "token_type": event.token_type.value,
        "injection_strategy": event.injection_strategy.value,
        "injection_location": event.injection_location,
        "injected_at": event.injected_at.isoformat(),
        "severity": event.severity.value,
        "triggered_at": event.triggered_at.isoformat(),
        "conversation_id": event.conversation_id,
        "tenant_id": event.tenant_id,
        "output_snippet": event.output_snippet,
        "full_output": event.full_output,
        "session_metadata": event.session_metadata,
        "forensic_notes": event.forensic_notes,
        "detection_surface": event.detection_surface,
        "incident_id": event.incident_id,
        "correlation_count": event.correlation_count,
    }


def _redact_payload(payload: dict) -> dict:
    out = dict(payload)
    secret = out.get("canary_value")
    out["canary_value"] = "[REDACTED]"
    if secret:
        for key in ("output_snippet", "full_output", "forensic_notes"):
            if out.get(key):
                out[key] = str(out[key]).replace(secret, "[REDACTED]")
    return out
