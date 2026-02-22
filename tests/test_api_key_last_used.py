import canari
import pytest

pytest.importorskip("fastapi")
starlette_testclient = pytest.importorskip("starlette.testclient")

from canari.api import create_app


def test_api_key_last_used_updates(tmp_path):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    created = honey.create_api_key(name="reader", key="reader-key", role="reader")

    app = create_app(db_path=str(db), api_key=None)
    client = starlette_testclient.TestClient(app)
    r = client.get("/v1/summary", headers={"X-API-Key": "reader-key"})
    assert r.status_code == 200

    keys = honey.list_api_keys()
    row = [k for k in keys if k["id"] == created["id"]][0]
    assert row["last_used_at"] is not None
