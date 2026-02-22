import json

import canari
from canari.cli import main


def test_cli_threat_feed(tmp_path, capsys):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    t = honey.generate(n_tokens=1, token_types=["api_key"])[0]
    honey.scan_output(f"leak {t.value}", context={"conversation_id": "conv-ti-cli"})

    rc = main(["--db", str(db), "threat-feed", "--limit", "100"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["events_analyzed"] == 1
