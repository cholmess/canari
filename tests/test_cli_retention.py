import json

import canari
from canari.cli import main


def test_cli_purge_alerts(tmp_path, capsys):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]
    honey.scan_output(f"leak {token.value}", context={"conversation_id": "conv-purge"})

    rc = main(["--db", str(db), "purge-alerts", "--older-than-days", "0"])
    assert rc == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["removed"] >= 1
