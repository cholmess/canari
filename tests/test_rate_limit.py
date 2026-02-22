from datetime import datetime, timedelta, timezone

from canari.models import AlertEvent, AlertSeverity, InjectionStrategy, TokenType
from canari.rate_limit import AlertRateLimiter


def _evt(i: int, t: datetime) -> AlertEvent:
    return AlertEvent(
        id=f"a-{i}",
        canary_id="cid",
        canary_value="v",
        token_type=TokenType.API_KEY,
        injection_strategy=InjectionStrategy.CONTEXT_APPENDIX,
        injection_location="ctx",
        injected_at=t - timedelta(minutes=1),
        severity=AlertSeverity.LOW,
        triggered_at=t,
        output_snippet="x",
        detection_surface="output",
    )


def test_rate_limit_blocks_after_threshold():
    rl = AlertRateLimiter(window_seconds=60, max_dispatches=2)
    base = datetime.now(timezone.utc)

    assert rl.should_dispatch(_evt(1, base)) is True
    assert rl.should_dispatch(_evt(2, base + timedelta(seconds=5))) is True
    assert rl.should_dispatch(_evt(3, base + timedelta(seconds=10))) is False


def test_rate_limit_resets_after_window():
    rl = AlertRateLimiter(window_seconds=10, max_dispatches=1)
    base = datetime.now(timezone.utc)

    assert rl.should_dispatch(_evt(1, base)) is True
    assert rl.should_dispatch(_evt(2, base + timedelta(seconds=1))) is False
    assert rl.should_dispatch(_evt(3, base + timedelta(seconds=12))) is True
