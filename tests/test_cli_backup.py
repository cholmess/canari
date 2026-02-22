import json

import canari
from canari.cli import main


def test_cli_backup_db(tmp_path, capsys):
    db = tmp_path / "canari.db"
    out = tmp_path / "canari-backup.db"

    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    honey.generate(n_tokens=1, token_types=["email"])

    rc = main(["--db", str(db), "backup-db", "--out", str(out)])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["bytes"] > 0
    assert out.exists()
