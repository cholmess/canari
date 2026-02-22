from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

import httpx

from canari.models import AlertEvent


class AlertDispatcher:
    def __init__(self):
        self._channels: list[Callable[[AlertEvent], None]] = []

    def add_webhook(self, url: str, headers: dict | None = None) -> None:
        hdrs = headers or {}

        def _send(event: AlertEvent) -> None:
            with httpx.Client(timeout=3.0) as client:
                client.post(url, json=event.model_dump(mode="json"), headers=hdrs)

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
                print(json.dumps(event.model_dump(mode="json"), default=str))
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
                f.write(json.dumps(event.model_dump(mode="json"), default=str) + "\n")

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
