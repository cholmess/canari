import json

from canari.cli import main


def test_cli_api_keys_flow(tmp_path, capsys):
    db = tmp_path / "canari.db"

    rc = main(["--db", str(db), "api-keys", "add", "--name", "ops", "--key", "topsecret", "--role", "reader"])
    assert rc == 0
    created = json.loads(capsys.readouterr().out)
    key_id = created["id"]

    rc = main(["--db", str(db), "api-keys", "list"])
    assert rc == 0
    listed = json.loads(capsys.readouterr().out)
    assert len(listed) == 1
    assert listed[0]["name"] == "ops"

    rc = main(["--db", str(db), "api-keys", "revoke", "--id", str(key_id)])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["revoked"] is True
