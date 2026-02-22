import json

import canari
from canari.cli import main


def test_cli_stats_and_export(tmp_path, capsys):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]
    honey.scan_output(f"leak {token.value}", context={"conversation_id": "conv-cli"})

    rc = main(["--db", str(db), "token-stats"])
    assert rc == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["total_tokens"] == 1

    out_file = tmp_path / "alerts.jsonl"
    rc = main(["--db", str(db), "export", "--format", "jsonl", "--out", str(out_file)])
    assert rc == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["exported"] == 1
    assert out_file.exists()
