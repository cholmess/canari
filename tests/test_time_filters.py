from datetime import datetime, timedelta, timezone

from canari.models import AlertEvent, AlertSeverity, InjectionStrategy, TokenType
from canari.registry import CanaryRegistry


def _evt(alert_id: str, triggered_at: datetime) -> AlertEvent:
    return AlertEvent(
        id=alert_id,
        canary_id="cid",
        canary_value="v",
        token_type=TokenType.API_KEY,
        injection_strategy=InjectionStrategy.CONTEXT_APPENDIX,
        injection_location="ctx",
        injected_at=triggered_at - timedelta(minutes=1),
        severity=AlertSeverity.LOW,
        triggered_at=triggered_at,
        output_snippet="s",
    )


def test_list_alerts_since_until(tmp_path):
    reg = CanaryRegistry(str(tmp_path / "canari.db"))
    now = datetime.now(timezone.utc)
    old = now - timedelta(days=2)
    mid = now - timedelta(days=1)
    new = now

    reg.record_alert(_evt("a-old", old))
    reg.record_alert(_evt("a-mid", mid))
    reg.record_alert(_evt("a-new", new))

    alerts = reg.list_alerts(limit=10, since=mid.isoformat())
    assert {a.id for a in alerts} == {"a-mid", "a-new"}

    alerts = reg.list_alerts(limit=10, until=mid.isoformat())
    assert {a.id for a in alerts} == {"a-old", "a-mid"}

    alerts = reg.list_alerts(limit=10, since=mid.isoformat(), until=mid.isoformat())
    assert {a.id for a in alerts} == {"a-mid"}
