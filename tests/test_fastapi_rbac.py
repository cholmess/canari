import canari
import pytest

pytest.importorskip("fastapi")
starlette_testclient = pytest.importorskip("starlette.testclient")

from canari.api import create_app


def test_fastapi_reader_forbidden_on_admin_endpoints(tmp_path):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    honey.create_api_key(name="reader", key="reader-key", role="reader")

    app = create_app(db_path=str(db), api_key=None)
    client = starlette_testclient.TestClient(app)

    assert client.get("/v1/audit", headers={"X-API-Key": "reader-key"}).status_code == 403
    assert client.get("/v1/threat-feed", headers={"X-API-Key": "reader-key"}).status_code == 403


def test_fastapi_tenant_scope_for_reader(tmp_path):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    t = honey.generate(n_tokens=1, token_types=["api_key"])[0]
    honey.scan_output(
        f"leak {t.value}",
        context={"conversation_id": "conv-tenant-a", "session_metadata": {"tenant_id": "tenant-a"}},
    )
    honey.scan_output(
        f"leak {t.value}",
        context={"conversation_id": "conv-tenant-b", "session_metadata": {"tenant_id": "tenant-b"}},
    )

    honey.create_api_key(name="reader-a", key="reader-a-key", role="reader", tenant_id="tenant-a")

    app = create_app(db_path=str(db), api_key=None)
    client = starlette_testclient.TestClient(app)

    r = client.get("/v1/alerts?limit=10", headers={"X-API-Key": "reader-a-key"})
    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == 1
    assert rows[0]["tenant_id"] == "tenant-a"
