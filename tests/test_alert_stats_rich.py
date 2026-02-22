from datetime import datetime, timedelta, timezone

from canari.models import AlertEvent, AlertSeverity, InjectionStrategy, TokenType
from canari.registry import CanaryRegistry


def _evt(i: int, conv: str, token_type: TokenType) -> AlertEvent:
    now = datetime.now(timezone.utc) + timedelta(seconds=i)
    return AlertEvent(
        id=f"a-{i}",
        canary_id=f"c-{i}",
        canary_value=f"v-{i}",
        token_type=token_type,
        injection_strategy=InjectionStrategy.CONTEXT_APPENDIX,
        injection_location="ctx",
        injected_at=now - timedelta(minutes=1),
        severity=AlertSeverity.LOW,
        triggered_at=now,
        conversation_id=conv,
        output_snippet="s",
    )


def test_alert_stats_rich_dimensions(tmp_path):
    reg = CanaryRegistry(str(tmp_path / "canari.db"))
    reg.record_alert(_evt(1, "conv-a", TokenType.API_KEY))
    reg.record_alert(_evt(2, "conv-a", TokenType.API_KEY))
    reg.record_alert(_evt(3, "conv-b", TokenType.EMAIL))

    stats = reg.alert_stats()
    assert stats["total_alerts"] == 3
    assert stats["by_token_type"]["api_key"] == 2
    assert stats["by_token_type"]["email"] == 1
    assert stats["top_conversations"][0]["conversation_id"] == "conv-a"
    assert stats["top_conversations"][0]["count"] == 2
