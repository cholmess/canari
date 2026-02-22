import canari
import pytest

pytest.importorskip("fastapi")
starlette_testclient = pytest.importorskip("starlette.testclient")

from canari.api import create_app


def test_fastapi_uses_registry_api_keys(tmp_path):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    honey.create_api_key(name="ops", key="registry-secret", role="reader")

    app = create_app(db_path=str(db), api_key=None)
    client = starlette_testclient.TestClient(app)

    assert client.get("/v1/summary").status_code == 401
    r = client.get("/v1/summary", headers={"X-API-Key": "registry-secret"})
    assert r.status_code == 200
