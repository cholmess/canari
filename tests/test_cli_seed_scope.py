import json

from canari.cli import main


def test_cli_seed_with_scope(tmp_path, capsys):
    db = tmp_path / "canari.db"
    rc = main(
        [
            "--db",
            str(db),
            "seed",
            "--n",
            "1",
            "--types",
            "api_key",
            "--tenant",
            "acme",
            "--app",
            "support-assistant",
        ]
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload) == 1
    assert payload[0]["tenant_id"] == "acme"
    assert payload[0]["application_id"] == "support-assistant"
