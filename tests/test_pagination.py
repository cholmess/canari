from datetime import datetime, timedelta, timezone

from canari.models import AlertEvent, AlertSeverity, InjectionStrategy, TokenType
from canari.registry import CanaryRegistry


def _evt(i: int) -> AlertEvent:
    t = datetime.now(timezone.utc) + timedelta(seconds=i)
    return AlertEvent(
        id=f"a-{i}",
        canary_id=f"c-{i}",
        canary_value=f"v-{i}",
        token_type=TokenType.API_KEY,
        injection_strategy=InjectionStrategy.CONTEXT_APPENDIX,
        injection_location="ctx",
        injected_at=t,
        severity=AlertSeverity.LOW,
        triggered_at=t,
        output_snippet="s",
    )


def test_list_alerts_offset(tmp_path):
    reg = CanaryRegistry(str(tmp_path / "canari.db"))
    for i in range(5):
        reg.record_alert(_evt(i))

    first = reg.list_alerts(limit=2, offset=0)
    second = reg.list_alerts(limit=2, offset=2)

    assert len(first) == 2
    assert len(second) == 2
    assert first[0].id != second[0].id
