from __future__ import annotations

import json
from datetime import timezone
from pathlib import Path
from typing import Callable

import httpx

from canari.models import AlertEvent


class AlertDispatcher:
    def __init__(self, canari_version: str = "0.1.0"):
        self._channels: list[Callable[[AlertEvent], None]] = []
        self.canari_version = canari_version

    def build_payload(self, event: AlertEvent) -> dict:
        triggered_at = event.triggered_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        injected_at = event.injected_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        return {
            "canari_version": self.canari_version,
            "alert_id": event.id,
            "severity": event.severity.value,
            "triggered_at": triggered_at,
            "canary": {
                "id": event.canary_id,
                "type": event.token_type.value,
                "value": event.canary_value,
                "injected_at": injected_at,
                "injection_strategy": event.injection_strategy.value,
                "injection_location": event.injection_location,
            },
            "trigger": {
                "output_snippet": event.output_snippet,
                "conversation_id": event.conversation_id,
                "session_metadata": event.session_metadata,
            },
            "forensic_notes": event.forensic_notes,
        }

    def add_webhook(self, url: str, headers: dict | None = None) -> None:
        hdrs = headers or {}

        def _send(event: AlertEvent) -> None:
            payload = self.build_payload(event)
            with httpx.Client(timeout=3.0) as client:
                client.post(url, json=payload, headers=hdrs)

        self._channels.append(_send)

    def add_slack(self, webhook_url: str) -> None:
        def _send(event: AlertEvent) -> None:
            text = (
                f"[CANARI] {event.severity.value.upper()} token leak detected: "
                f"{event.token_type.value} {event.canary_value}"
            )
            with httpx.Client(timeout=3.0) as client:
                client.post(webhook_url, json={"text": text})

        self._channels.append(_send)

    def add_stdout(self, format: str = "rich") -> None:  # noqa: A002
        def _send(event: AlertEvent) -> None:
            if format == "json":
                print(json.dumps(self.build_payload(event), default=str))
            else:
                print(
                    f"[CANARI ALERT] severity={event.severity.value} "
                    f"type={event.token_type.value} canary={event.canary_value}"
                )

        self._channels.append(_send)

    def add_file(self, path: str) -> None:
        log_path = Path(path)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        def _send(event: AlertEvent) -> None:
            with log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(self.build_payload(event), default=str) + "\n")

        self._channels.append(_send)

    def add_callback(self, fn: Callable[[AlertEvent], None]) -> None:
        self._channels.append(fn)

    def dispatch(self, event: AlertEvent) -> None:
        for channel in self._channels:
            try:
                channel(event)
            except Exception:
                # Alert dispatch never crashes application code.
                continue
