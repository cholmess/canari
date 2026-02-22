import json

import canari
import pytest
from canari.cli import main

pytest.importorskip("fastapi")
starlette_testclient = pytest.importorskip("starlette.testclient")

from canari.api import create_app


def test_cli_evidence_pack(tmp_path, capsys):
    db = tmp_path / "canari.db"
    out = tmp_path / "evidence.json"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    token = honey.generate(n_tokens=1, token_types=["api_key"], application_id="app-e")
    honey.scan_output(
        f"leak {token[0].value}",
        context={"conversation_id": "conv-ev", "session_metadata": {"application_id": "app-e"}},
    )

    rc = main(["--db", str(db), "evidence-pack", "--limit", "100", "--app", "app-e", "--out", str(out)])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["written"] is True
    body = json.loads(out.read_text(encoding="utf-8"))
    assert body["evidence_version"] == "v1"
    assert body["schema_version"] == 1
    assert body["scope"]["application_id"] == "app-e"


def test_fastapi_evidence_pack(tmp_path):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    honey.create_api_key(name="admin", key="admin-key", role="admin")
    token = honey.generate(n_tokens=1, token_types=["api_key"], application_id="app-z")[0]
    honey.scan_output(
        f"leak {token.value}",
        context={"conversation_id": "conv-api-ev", "session_metadata": {"application_id": "app-z"}},
    )

    app = create_app(db_path=str(db), api_key=None)
    client = starlette_testclient.TestClient(app)

    r = client.get("/v1/compliance/evidence?limit=100&app=app-z", headers={"X-API-Key": "admin-key"})
    assert r.status_code == 200
    body = r.json()
    assert body["evidence_version"] == "v1"
    assert body["schema_version"] == 1
    assert body["scope"]["application_id"] == "app-z"
