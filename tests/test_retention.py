from datetime import datetime, timedelta, timezone

from canari.models import AlertEvent, AlertSeverity, InjectionStrategy, TokenType
from canari.registry import CanaryRegistry


def _mk_event(alert_id: str, triggered_at: datetime) -> AlertEvent:
    return AlertEvent(
        id=alert_id,
        canary_id="cid",
        canary_value="api_canari_x",
        token_type=TokenType.API_KEY,
        injection_strategy=InjectionStrategy.CONTEXT_APPENDIX,
        injection_location="ctx",
        injected_at=triggered_at - timedelta(hours=1),
        severity=AlertSeverity.LOW,
        triggered_at=triggered_at,
        conversation_id="conv-ret",
        output_snippet="snippet",
        forensic_notes="note",
    )


def test_purge_alerts_older_than(tmp_path):
    reg = CanaryRegistry(str(tmp_path / "canari.db"))
    now = datetime.now(timezone.utc)
    old = _mk_event("a-old", now - timedelta(days=10))
    new = _mk_event("a-new", now - timedelta(hours=2))

    reg.record_alert(old)
    reg.record_alert(new)

    removed = reg.purge_alerts_older_than(days=7)
    assert removed == 1

    alerts = reg.list_alerts(limit=10)
    ids = {a.id for a in alerts}
    assert ids == {"a-new"}
