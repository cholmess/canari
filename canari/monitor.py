from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from canari.detection import ExfiltrationAnalyzer
from canari.models import AlertEvent, CanaryToken
from canari.registry import CanaryRegistry


class EgressMonitor:
    def __init__(self, registry: CanaryRegistry):
        self.registry = registry
        self.analyzer = ExfiltrationAnalyzer()

    def inspect_http_request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: Any = None,
        context: dict | None = None,
    ) -> list[AlertEvent]:
        context = context or {}
        headers = headers or {}
        body_text = self._stringify_body(body)

        surface = "\n".join(
            [
                f"method={method}",
                f"url={url}",
                f"headers={dict(headers)}",
                f"body={body_text}",
            ]
        )

        hits: list[CanaryToken] = []
        tenant_id = (context.get("session_metadata", {}) or {}).get("tenant_id") or context.get("tenant_id")
        application_id = (context.get("session_metadata", {}) or {}).get("application_id") or context.get("application_id")
        for token in self.registry.list_active(tenant_id=tenant_id, application_id=application_id):
            if token.value in surface:
                hits.append(token)

        now = datetime.now(timezone.utc)
        events: list[AlertEvent] = []
        for token in hits:
            idx = surface.find(token.value)
            snippet_start = max(0, idx - 80)
            snippet_end = min(len(surface), idx + len(token.value) + 80)
            snippet = surface[snippet_start:snippet_end]
            assessment = self.analyzer.assess(token, surface, len(hits))
            delta = now - token.injection_timestamp.astimezone(timezone.utc)
            interval = str(delta).split(".", maxsplit=1)[0]
            events.append(
                AlertEvent(
                    id=str(uuid.uuid4()),
                    canary_id=token.id,
                    canary_value=token.value,
                    token_type=token.token_type,
                    injection_strategy=token.injection_strategy,
                    injection_location=token.injection_location,
                    injected_at=token.injection_timestamp,
                    severity=assessment.severity,
                    triggered_at=now,
                    conversation_id=context.get("conversation_id"),
                    output_snippet=snippet,
                    full_output=surface,
                    session_metadata=context.get(
                        "session_metadata",
                        {"method": method, "url": url},
                    ),
                    forensic_notes=(
                        "Canary token detected in outbound HTTP request. "
                        f"Assessment={assessment.reason}. Injection-to-trigger interval={interval}."
                    ),
                    detection_surface="network_egress",
                    tenant_id=(context.get("session_metadata", {}) or {}).get("tenant_id") or context.get("tenant_id"),
                    application_id=(context.get("session_metadata", {}) or {}).get("application_id")
                    or context.get("application_id"),
                )
            )
        return events

    @staticmethod
    def _stringify_body(body: Any) -> str:
        if body is None:
            return ""
        if isinstance(body, (str, bytes)):
            return body.decode("utf-8", errors="ignore") if isinstance(body, bytes) else body
        if isinstance(body, dict):
            return json.dumps(body, sort_keys=True)
        return str(body)
