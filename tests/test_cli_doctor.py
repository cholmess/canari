import json

from canari.cli import main


def test_cli_doctor(tmp_path, capsys):
    db = tmp_path / "canari.db"

    rc = main(["--db", str(db), "doctor"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["ok"] is True
    assert payload["db_path"] == str(db)
    assert payload["checks"]["tables"]["canary_tokens"] is True
    assert payload["checks"]["tables"]["alert_events"] is True
