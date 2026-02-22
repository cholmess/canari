import json
from datetime import datetime, timedelta, timezone

from canari.cli import main
from canari.models import AlertEvent, AlertSeverity, InjectionStrategy, TokenType
from canari.registry import CanaryRegistry


def test_cli_alerts_since_filter(tmp_path, capsys):
    db = tmp_path / "canari.db"
    reg = CanaryRegistry(str(db))

    now = datetime.now(timezone.utc)
    old = now - timedelta(days=2)

    reg.record_alert(
        AlertEvent(
            id="a-old",
            canary_id="cid",
            canary_value="v",
            token_type=TokenType.API_KEY,
            injection_strategy=InjectionStrategy.CONTEXT_APPENDIX,
            injection_location="ctx",
            injected_at=old - timedelta(minutes=1),
            severity=AlertSeverity.LOW,
            triggered_at=old,
            output_snippet="s",
        )
    )
    reg.record_alert(
        AlertEvent(
            id="a-new",
            canary_id="cid",
            canary_value="v",
            token_type=TokenType.API_KEY,
            injection_strategy=InjectionStrategy.CONTEXT_APPENDIX,
            injection_location="ctx",
            injected_at=now - timedelta(minutes=1),
            severity=AlertSeverity.LOW,
            triggered_at=now,
            output_snippet="s",
        )
    )

    rc = main(["--db", str(db), "alerts", "--since", (now - timedelta(hours=1)).isoformat(), "--limit", "10"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload) == 1
    assert payload[0]["id"] == "a-new"
