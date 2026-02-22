import json

from canari.cli import main


def test_cli_serve_api_check(tmp_path, capsys):
    db = tmp_path / "canari.db"
    rc = main(["--db", str(db), "serve-api", "--check", "--port", "8001"])
    payload = json.loads(capsys.readouterr().out)
    if rc == 0:
        assert payload["ok"] is True
        assert payload["app"] == "fastapi"
    else:
        assert payload["error"] in {"fastapi_unavailable", "uvicorn_unavailable"}
