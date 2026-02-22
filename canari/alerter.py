from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import timezone
from pathlib import Path
from typing import Callable

import httpx

from canari.models import AlertEvent


class AlertDispatcher:
    def __init__(self, canari_version: str = "0.1.0"):
        self._channels: list[Callable[[AlertEvent], None]] = []
        self.canari_version = canari_version
        self.dispatch_successes = 0
        self.dispatch_failures = 0

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
                "detection_surface": event.detection_surface,
                "output_snippet": event.output_snippet,
                "conversation_id": event.conversation_id,
                "incident_id": event.incident_id,
                "correlation_count": event.correlation_count,
                "session_metadata": event.session_metadata,
            },
            "forensic_notes": event.forensic_notes,
        }

    def add_webhook(
        self,
        url: str,
        headers: dict | None = None,
        *,
        retries: int = 1,
        backoff_seconds: float = 0.25,
        signing_secret: str | None = None,
    ) -> None:
        hdrs = headers or {}

        def _send(event: AlertEvent) -> None:
            payload = self.build_payload(event)
            request_headers = dict(hdrs)
            if signing_secret:
                request_headers.update(self._sign_headers(payload, signing_secret))
            self._post_with_retry(
                url=url,
                payload=payload,
                headers=request_headers,
                retries=retries,
                backoff_seconds=backoff_seconds,
            )

        self._channels.append(_send)

    def add_slack(self, webhook_url: str, *, retries: int = 1, backoff_seconds: float = 0.25) -> None:
        def _send(event: AlertEvent) -> None:
            text = (
                f"[CANARI] {event.severity.value.upper()} token leak detected: "
                f"{event.token_type.value} {event.canary_value}"
            )
            self._post_with_retry(
                url=webhook_url,
                payload={"text": text},
                headers={},
                retries=retries,
                backoff_seconds=backoff_seconds,
            )

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
                self.dispatch_successes += 1
            except Exception:
                # Alert dispatch never crashes application code.
                self.dispatch_failures += 1
                continue

    def health(self) -> dict:
        return {
            "channels": len(self._channels),
            "dispatch_successes": self.dispatch_successes,
            "dispatch_failures": self.dispatch_failures,
        }

    @staticmethod
    def _sleep(seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)

    def _post_with_retry(
        self,
        *,
        url: str,
        payload: dict,
        headers: dict,
        retries: int,
        backoff_seconds: float,
    ) -> None:
        attempts = max(1, retries)
        last_err = None
        for attempt in range(attempts):
            try:
                with httpx.Client(timeout=3.0) as client:
                    resp = client.post(url, json=payload, headers=headers)
                if hasattr(resp, "is_success") and not resp.is_success:
                    raise RuntimeError(f"non-success response from alert channel: {getattr(resp, 'status_code', 'unknown')}")
                return
            except Exception as exc:
                last_err = exc
                if attempt < attempts - 1:
                    self._sleep(backoff_seconds)
        if last_err is not None:
            raise last_err

    @staticmethod
    def _sign_headers(payload: dict, secret: str) -> dict:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        signature = hmac.new(secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()
        return {
            "X-Canari-Signature": f"sha256={signature}",
            "X-Canari-Signature-Version": "v1",
        }

    @staticmethod
    def verify_signature(payload: dict, headers: dict, secret: str) -> bool:
        provided = headers.get("X-Canari-Signature", "")
        if not provided.startswith("sha256="):
            return False
        expected = AlertDispatcher._sign_headers(payload, secret)["X-Canari-Signature"]
        return hmac.compare_digest(provided, expected)
