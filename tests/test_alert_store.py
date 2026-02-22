from datetime import datetime, timezone

from canari.models import AlertEvent, AlertSeverity, InjectionStrategy, TokenType
from canari.registry import CanaryRegistry


def _event(alert_id: str, severity: AlertSeverity, surface: str, conv: str) -> AlertEvent:
    now = datetime.now(timezone.utc)
    return AlertEvent(
        id=alert_id,
        canary_id="cid",
        canary_value="api_canari_x",
        token_type=TokenType.API_KEY,
        injection_strategy=InjectionStrategy.CONTEXT_APPENDIX,
        injection_location="ctx",
        injected_at=now,
        severity=severity,
        triggered_at=now,
        conversation_id=conv,
        output_snippet="snippet",
        session_metadata={"k": "v"},
        forensic_notes="note",
        detection_surface=surface,
        incident_id="inc-1",
        correlation_count=2,
    )


def test_record_and_list_alerts(tmp_path):
    reg = CanaryRegistry(str(tmp_path / "canari.db"))
    reg.record_alert(_event("a1", AlertSeverity.LOW, "output", "conv-1"))
    reg.record_alert(_event("a2", AlertSeverity.HIGH, "network_egress", "conv-1"))

    alerts = reg.list_alerts(limit=10)
    assert len(alerts) == 2
    assert alerts[0].id in {"a1", "a2"}

    filtered = reg.list_alerts(limit=10, severity="high")
    assert len(filtered) == 1
    assert filtered[0].severity == AlertSeverity.HIGH


def test_alert_stats(tmp_path):
    reg = CanaryRegistry(str(tmp_path / "canari.db"))
    reg.record_alert(_event("a1", AlertSeverity.LOW, "output", "conv-1"))
    reg.record_alert(_event("a2", AlertSeverity.CRITICAL, "network_egress", "conv-2"))

    stats = reg.alert_stats()
    assert stats["total_alerts"] == 2
    assert stats["by_severity"]["low"] == 1
    assert stats["by_severity"]["critical"] == 1
    assert stats["by_surface"]["output"] == 1
