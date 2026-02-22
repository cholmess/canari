import json

from canari.cli import main


def test_cli_serve_dashboard_check(tmp_path, capsys):
    db = tmp_path / "canari.db"
    rc = main(["--db", str(db), "serve-dashboard", "--host", "127.0.0.1", "--port", "0", "--check"])
    assert rc in (0, 1)
    payload = json.loads(capsys.readouterr().out)
    if rc == 0:
        assert payload["url"].startswith("http://127.0.0.1:")
    else:
        assert payload["error"] == "dashboard_bind_failed"
