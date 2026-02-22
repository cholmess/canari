import json

import canari
import pytest
from canari.cli import main

pytest.importorskip("fastapi")
starlette_testclient = pytest.importorskip("starlette.testclient")

from canari.api import create_app


def test_cli_incident_dossier(tmp_path, capsys):
    db = tmp_path / "canari.db"
    out = tmp_path / "dossier.json"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    token = honey.generate(n_tokens=1, token_types=["api_key"], application_id="ops-app")[0]
    events = honey.scan_output(
        f"leak {token.value}",
        context={"conversation_id": "conv-dossier", "session_metadata": {"application_id": "ops-app"}},
    )
    incident_id = events[0].incident_id

    rc = main(
        [
            "--db",
            str(db),
            "incident-dossier",
            "--incident",
            incident_id,
            "--app",
            "ops-app",
            "--out",
            str(out),
        ]
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["written"] is True
    body = json.loads(out.read_text(encoding="utf-8"))
    assert body["found"] is True
    assert body["incident_id"] == incident_id


def test_fastapi_incident_dossier(tmp_path):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    honey.create_api_key(name="admin", key="admin-key", role="admin")
    t = honey.generate(n_tokens=1, token_types=["api_key"], application_id="app-ir")[0]
    e = honey.scan_output(
        f"leak {t.value}",
        context={"conversation_id": "conv-ir", "session_metadata": {"application_id": "app-ir"}},
    )[0]

    app = create_app(db_path=str(db), api_key=None)
    client = starlette_testclient.TestClient(app)
    r = client.get(
        f"/v1/compliance/incidents/{e.incident_id}?app=app-ir",
        headers={"X-API-Key": "admin-key"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["found"] is True
    assert body["incident_id"] == e.incident_id
