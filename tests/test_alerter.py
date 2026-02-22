import json
from datetime import datetime, timezone

from canari.alerter import AlertDispatcher
from canari.models import AlertEvent, AlertSeverity, InjectionStrategy, TokenType


def test_build_payload_shape():
    dispatcher = AlertDispatcher(canari_version="0.1.0")
    event = AlertEvent(
        id="alert-1",
        canary_id="canary-1",
        canary_value="sk_test_CANARI_abc",
        token_type=TokenType.STRIPE_KEY,
        injection_strategy=InjectionStrategy.DOCUMENT_METADATA,
        injection_location="vector store doc A",
        injected_at=datetime(2026, 2, 22, 9, 0, 0, tzinfo=timezone.utc),
        severity=AlertSeverity.HIGH,
        triggered_at=datetime(2026, 2, 22, 14, 30, 0, tzinfo=timezone.utc),
        conversation_id="conv-1",
        output_snippet="...sk_test_CANARI_abc...",
        session_metadata={"env": "test"},
        forensic_notes="Token appeared in output",
    )

    payload = dispatcher.build_payload(event)
    assert payload["canari_version"] == "0.1.0"
    assert payload["canary"]["id"] == "canary-1"
    assert payload["trigger"]["conversation_id"] == "conv-1"
    assert payload["trigger"]["detection_surface"] == "output"
    assert payload["severity"] == "high"


def test_add_file_writes_payload(tmp_path):
    log_path = tmp_path / "alerts.log"
    dispatcher = AlertDispatcher()
    dispatcher.add_file(str(log_path))

    event = AlertEvent(
        id="alert-2",
        canary_id="canary-2",
        canary_value="AKIAABCDEF1234567890",
        token_type=TokenType.AWS_KEY,
        injection_strategy=InjectionStrategy.SYSTEM_PROMPT_COMMENT,
        injection_location="system prompt",
        injected_at=datetime.now(timezone.utc),
        severity=AlertSeverity.HIGH,
        output_snippet="...AKIAABCDEF1234567890...",
    )

    dispatcher.dispatch(event)

    line = log_path.read_text(encoding="utf-8").strip()
    payload = json.loads(line)
    assert payload["alert_id"] == "alert-2"
