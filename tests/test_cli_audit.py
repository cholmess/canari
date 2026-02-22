import json

import canari
from canari.cli import main


def test_cli_audit_log(tmp_path, capsys):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    honey.generate(n_tokens=1, token_types=["email"])
    honey.rotate_canaries(n_tokens=1, token_types=["email"])

    rc = main(["--db", str(db), "audit-log", "--limit", "10"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload) >= 1
    assert "action" in payload[0]
