import json

import canari
import pytest
from canari.cli import main

pytest.importorskip("fastapi")
starlette_testclient = pytest.importorskip("starlette.testclient")

from canari.api import create_app


def test_default_application_context_and_filter(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))
    honey.alerter._channels = []
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]

    honey.set_default_application("app-a")
    honey.scan_output(f"leak {token.value}", context={"conversation_id": "conv-a"})
    honey.clear_default_application()
    honey.scan_output(f"leak {token.value}", context={"conversation_id": "conv-b", "application_id": "app-b"})

    app_a = honey.alert_history(limit=10, application_id="app-a")
    app_b = honey.alert_history(limit=10, application_id="app-b")
    assert len(app_a) == 1
    assert len(app_b) == 1
    assert app_a[0].application_id == "app-a"
    assert app_b[0].application_id == "app-b"


def test_cli_alerts_with_app_filter(tmp_path, capsys):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]
    honey.scan_output(f"leak {token.value}", context={"conversation_id": "conv-cli-app", "application_id": "my-app"})

    rc = main(["--db", str(db), "alerts", "--limit", "10", "--app", "my-app"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload) == 1
    assert payload[0]["application_id"] == "my-app"


def test_fastapi_alerts_with_app_filter(tmp_path):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]
    honey.scan_output(f"leak {token.value}", context={"conversation_id": "conv-api-app", "application_id": "app-api"})

    app = create_app(db_path=str(db), api_key="secret")
    client = starlette_testclient.TestClient(app)
    r = client.get("/v1/alerts?limit=10&app=app-api", headers={"X-API-Key": "secret"})
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 1
    assert body[0]["application_id"] == "app-api"
