from unittest.mock import patch

from canari.alerter import AlertDispatcher
from canari.models import AlertEvent, AlertSeverity, InjectionStrategy, TokenType
from datetime import datetime, timezone


class DummyClient:
    def __init__(self, outcomes):
        self.outcomes = outcomes
        self.calls = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def post(self, *args, **kwargs):
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class DummyResp:
    def __init__(self, ok=True):
        self.is_success = ok


def _event() -> AlertEvent:
    now = datetime.now(timezone.utc)
    return AlertEvent(
        id="a1",
        canary_id="c1",
        canary_value="v1",
        token_type=TokenType.API_KEY,
        injection_strategy=InjectionStrategy.CONTEXT_APPENDIX,
        injection_location="ctx",
        injected_at=now,
        severity=AlertSeverity.LOW,
        triggered_at=now,
        output_snippet="s",
    )


def test_webhook_retries_then_succeeds():
    dispatcher = AlertDispatcher()
    outcomes = [RuntimeError("boom"), DummyResp(ok=True)]

    with patch("canari.alerter.httpx.Client", return_value=DummyClient(outcomes)):
        dispatcher.add_webhook("https://example.com", retries=2, backoff_seconds=0)
        dispatcher.dispatch(_event())

    health = dispatcher.health()
    assert health["dispatch_successes"] == 1


def test_dispatch_failure_counted():
    dispatcher = AlertDispatcher()
    outcomes = [RuntimeError("boom"), RuntimeError("boom2")]

    with patch("canari.alerter.httpx.Client", return_value=DummyClient(outcomes)):
        dispatcher.add_webhook("https://example.com", retries=2, backoff_seconds=0)
        dispatcher.dispatch(_event())

    health = dispatcher.health()
    assert health["dispatch_failures"] == 1
