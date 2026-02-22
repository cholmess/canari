import canari
import pytest


fastapi = pytest.importorskip("fastapi")
starlette_testclient = pytest.importorskip("starlette.testclient")

from canari.api import create_app


def test_fastapi_health_and_protected_endpoints(tmp_path):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]
    honey.scan_output(f"leak {token.value}", context={"conversation_id": "conv-api"})

    app = create_app(db_path=str(db), api_key="secret")
    client = starlette_testclient.TestClient(app)

    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["ok"] is True

    assert client.get("/v1/summary").status_code == 401
    r = client.get("/v1/summary", headers={"X-API-Key": "secret"})
    assert r.status_code == 200
    assert r.json()["alerts"]["total_alerts"] >= 1

    r = client.get("/v1/alerts?limit=10", headers={"X-API-Key": "secret"})
    assert r.status_code == 200
    assert len(r.json()) == 1

    r = client.get("/v1/alert-stats", headers={"X-API-Key": "secret"})
    assert r.status_code == 200
    assert r.json()["total_alerts"] >= 1

    r = client.get("/v1/threat-feed", headers={"X-API-Key": "secret"})
    assert r.status_code == 200
    assert r.json()["events_analyzed"] >= 1

    r = client.post("/v1/threat-sharing", headers={"X-API-Key": "secret"}, json={"opt_in_enabled": True})
    assert r.status_code == 200
    assert r.json()["opt_in_enabled"] is True

    r = client.get("/v1/threat-sharing", headers={"X-API-Key": "secret"})
    assert r.status_code == 200
    assert r.json()["opt_in_enabled"] is True

    r = client.post(
        "/v1/network-signatures/import",
        headers={"X-API-Key": "secret"},
        json={"signatures": [{"signature": "abc123def4567890", "count": 1, "token_type": "api_key"}]},
    )
    assert r.status_code == 200
    assert r.json()["imported"] == 1

    r = client.get("/v1/network-signatures?limit=10&offset=0", headers={"X-API-Key": "secret"})
    assert r.status_code == 200
    assert len(r.json()) >= 1
