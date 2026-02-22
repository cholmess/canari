import json

from canari.cli import main


def test_cli_alerter_health(tmp_path, capsys):
    db = tmp_path / "canari.db"
    rc = main(["--db", str(db), "alerter-health"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["channels"] == 0
    assert payload["dispatch_successes"] == 0
    assert payload["dispatch_failures"] == 0
