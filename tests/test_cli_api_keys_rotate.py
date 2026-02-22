import json

from canari.cli import main


def test_cli_api_key_rotate(tmp_path, capsys):
    db = tmp_path / "canari.db"

    rc = main(["--db", str(db), "api-keys", "add", "--name", "ops", "--key", "old", "--role", "admin"])
    assert rc == 0
    created = json.loads(capsys.readouterr().out)

    rc = main(["--db", str(db), "api-keys", "rotate", "--id", str(created["id"]), "--new-key", "new"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["old_key_revoked"] is True
    assert payload["new_key"]["active"] is True
