import json

import canari
from canari.cli import main


def test_cli_alert_stats_scoped(tmp_path, capsys):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]
    honey.scan_output(
        f"leak {token.value}",
        context={"conversation_id": "conv-stats", "session_metadata": {"tenant_id": "acme", "application_id": "app-a"}},
    )

    rc = main(["--db", str(db), "alert-stats", "--tenant", "acme", "--app", "app-a"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["total_alerts"] == 1
    assert payload["by_application"]["app-a"] == 1
