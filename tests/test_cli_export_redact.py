import json

import canari
from canari.cli import main


def test_cli_export_redact(tmp_path, capsys):
    db = tmp_path / "canari.db"
    out = tmp_path / "alerts.jsonl"

    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]
    honey.scan_output(f"leak {token.value}", context={"conversation_id": "conv-r"})

    rc = main(["--db", str(db), "export", "--format", "jsonl", "--out", str(out), "--redact"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["exported"] == 1

    row = json.loads(out.read_text(encoding="utf-8").strip())
    assert row["canary_value"] == "[REDACTED]"
