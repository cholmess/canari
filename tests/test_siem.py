import json

import canari
import pytest
from canari.cli import main

pytest.importorskip("fastapi")
starlette_testclient = pytest.importorskip("starlette.testclient")

from canari.api import create_app


def test_siem_events_client_and_cli(tmp_path, capsys):
    db = tmp_path / "canari.db"
    out = tmp_path / "siem.jsonl"

    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]
    honey.scan_output(f"leak {token.value}", context={"conversation_id": "conv-siem"})

    rows = honey.siem_events(limit=10)
    assert len(rows) == 1
    assert rows[0]["event_type"] == "canary_leak"

    rc = main(["--db", str(db), "siem-export", "--limit", "10", "--format", "jsonl", "--out", str(out)])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["exported"] == 1
    assert out.exists()

    out_cef = tmp_path / "siem.cef"
    rc = main(["--db", str(db), "siem-export", "--limit", "10", "--format", "cef", "--out", str(out_cef)])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["format"] == "cef"
    assert "CEF:0|Canari|IDS|" in out_cef.read_text(encoding="utf-8")


def test_siem_events_fastapi(tmp_path):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    honey.create_api_key(name="admin", key="admin-key", role="admin")
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]
    honey.scan_output(f"leak {token.value}", context={"conversation_id": "conv-siem-api"})

    app = create_app(db_path=str(db), api_key=None)
    client = starlette_testclient.TestClient(app)
    r = client.get("/v1/siem/events?limit=10", headers={"X-API-Key": "admin-key"})
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 1
    assert body[0]["event_type"] == "canary_leak"

    r = client.get("/v1/siem/cef?limit=10", headers={"X-API-Key": "admin-key"})
    assert r.status_code == 200
    cef = r.json()
    assert len(cef) == 1
    assert cef[0].startswith("CEF:0|Canari|IDS|")
