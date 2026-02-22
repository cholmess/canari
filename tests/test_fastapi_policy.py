import canari
import pytest

pytest.importorskip("fastapi")
starlette_testclient = pytest.importorskip("starlette.testclient")

from canari.api import create_app


def test_fastapi_policy_admin_set_and_get(tmp_path):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    honey.create_api_key(name="admin", key="admin-key", role="admin")

    app = create_app(db_path=str(db), api_key=None)
    client = starlette_testclient.TestClient(app)

    r = client.post(
        "/v1/policy",
        headers={"X-API-Key": "admin-key"},
        json={
            "min_dispatch_severity": "high",
            "rate_window_seconds": 90,
            "rate_max_dispatches": 2,
            "retention_days": 45,
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["saved"] is True

    r = client.get("/v1/policy", headers={"X-API-Key": "admin-key"})
    assert r.status_code == 200
    body = r.json()
    assert body["min_dispatch_severity"] == "high"
    assert body["rate_limit"]["window_seconds"] == 90
    assert body["rate_limit"]["max_dispatches"] == 2
    assert body["retention_days"] == 45


def test_fastapi_policy_reader_forbidden(tmp_path):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    honey.create_api_key(name="reader", key="reader-key", role="reader")

    app = create_app(db_path=str(db), api_key=None)
    client = starlette_testclient.TestClient(app)

    assert client.get("/v1/policy", headers={"X-API-Key": "reader-key"}).status_code == 403
    assert client.post("/v1/policy", headers={"X-API-Key": "reader-key"}, json={}).status_code == 403
