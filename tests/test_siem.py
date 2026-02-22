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

    ingest_file = tmp_path / "ingest.json"
    ingest_file.write_text(
        json.dumps(
            {
                "events": [
                    {
                        "event_type": "canary_leak",
                        "severity": "high",
                        "token_type": "api_key",
                        "detection_surface": "siem_stream",
                        "snippet": "indicator-x",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    rc = main(["--db", str(db), "siem-ingest", "--in", str(ingest_file), "--source", "splunk"])
    assert rc == 0
    ingest_payload = json.loads(capsys.readouterr().out)
    assert ingest_payload["stored_events"] == 1

    rc = main(["--db", str(db), "siem-external", "--limit", "10", "--offset", "0"])
    assert rc == 0
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) >= 1


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

    r = client.post(
        "/v1/siem/ingest",
        headers={"X-API-Key": "admin-key"},
        json={
            "source": "datadog",
            "events": [
                {
                    "event_type": "canary_leak",
                    "severity": "medium",
                    "token_type": "api_key",
                    "detection_surface": "siem_stream",
                    "snippet": "abc",
                }
            ],
        },
    )
    assert r.status_code == 200
    assert r.json()["stored_events"] == 1

    r = client.get("/v1/siem/external?limit=10&offset=0", headers={"X-API-Key": "admin-key"})
    assert r.status_code == 200
    assert len(r.json()) >= 1
