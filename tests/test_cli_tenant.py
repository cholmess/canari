import json

import canari
from canari.cli import main


def test_cli_alerts_tenant_filter(tmp_path, capsys):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    t = honey.generate(n_tokens=1, token_types=["api_key"])[0]
    honey.scan_output(
        f"leak {t.value}",
        context={"conversation_id": "c1", "session_metadata": {"tenant_id": "tenant-a"}},
    )

    rc = main(["--db", str(db), "alerts", "--tenant", "tenant-a", "--limit", "10"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload) == 1
    assert payload[0]["tenant_id"] == "tenant-a"
