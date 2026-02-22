import json

import canari
from canari.cli import main


def test_cli_threat_share_enable_and_show(tmp_path, capsys):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []

    assert main(["--db", str(db), "threat-share", "enable"]) == 0
    enabled_payload = json.loads(capsys.readouterr().out)
    assert enabled_payload["opt_in_enabled"] is True

    assert main(["--db", str(db), "threat-share", "show"]) == 0
    show_payload = json.loads(capsys.readouterr().out)
    assert show_payload["opt_in_enabled"] is True


def test_cli_threat_import_and_network_signatures(tmp_path, capsys):
    db = tmp_path / "canari.db"
    in_file = tmp_path / "bundle.json"
    bundle = {
        "schema": "canari-threat-share-v1",
        "feed": {
            "signatures": [
                {
                    "signature": "abc123def4567890",
                    "count": 2,
                    "token_type": "api_key",
                    "surface": "llm_output",
                    "severity": "low",
                }
            ]
        },
    }
    in_file.write_text(json.dumps(bundle), encoding="utf-8")

    assert main(["--db", str(db), "threat-import", "--in", str(in_file), "--source", "community"]) == 0
    imported = json.loads(capsys.readouterr().out)
    assert imported["imported"] == 1

    assert main(["--db", str(db), "network-signatures", "--limit", "10", "--offset", "0"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 1
    assert rows[0]["signature"] == "abc123def4567890"
