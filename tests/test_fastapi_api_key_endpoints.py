import canari
import pytest

pytest.importorskip("fastapi")
starlette_testclient = pytest.importorskip("starlette.testclient")

from canari.api import create_app


def test_fastapi_admin_api_key_endpoints(tmp_path):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    honey.create_api_key(name="admin", key="admin-key", role="admin")

    app = create_app(db_path=str(db), api_key=None)
    client = starlette_testclient.TestClient(app)

    r = client.post(
        "/v1/api-keys",
        headers={"X-API-Key": "admin-key"},
        json={
            "name": "reader",
            "key": "reader-key",
            "role": "reader",
            "tenant_id": "acme",
            "application_id": "helpdesk-app",
        },
    )
    assert r.status_code == 200
    created = r.json()
    assert created["role"] == "reader"
    assert created["application_id"] == "helpdesk-app"

    r = client.get("/v1/api-keys", headers={"X-API-Key": "admin-key"})
    assert r.status_code == 200
    assert len(r.json()) >= 2

    r = client.post(f"/v1/api-keys/{created['id']}/rotate", headers={"X-API-Key": "admin-key"}, json={"new_key": "reader-key-2"})
    assert r.status_code == 200
    assert r.json()["old_key_revoked"] is True


def test_fastapi_reader_cannot_manage_api_keys(tmp_path):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    honey.create_api_key(name="reader", key="reader-key", role="reader")

    app = create_app(db_path=str(db), api_key=None)
    client = starlette_testclient.TestClient(app)

    assert client.get("/v1/api-keys", headers={"X-API-Key": "reader-key"}).status_code == 403
    assert client.post(
        "/v1/api-keys",
        headers={"X-API-Key": "reader-key"},
        json={"name": "x", "key": "y"},
    ).status_code == 403
