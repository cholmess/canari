import json

import canari
from canari.cli import main


def test_cli_rotate_canaries(tmp_path, capsys):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    honey.generate(n_tokens=2, token_types=["api_key"])

    rc = main(["--db", str(db), "rotate-canaries", "--n", "3", "--types", "email,api_key"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["deactivated"] == 2
    assert payload["generated"] == 3
