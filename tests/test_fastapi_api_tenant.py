import canari
import pytest

pytest.importorskip("fastapi")
starlette_testclient = pytest.importorskip("starlette.testclient")

from canari.api import create_app


def test_fastapi_alert_tenant_filter(tmp_path):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    t = honey.generate(n_tokens=1, token_types=["api_key"])[0]
    honey.scan_output(
        f"leak {t.value}",
        context={"conversation_id": "conv-api-tenant", "session_metadata": {"tenant_id": "acme"}},
    )

    app = create_app(db_path=str(db), api_key=None)
    client = starlette_testclient.TestClient(app)

    r = client.get("/v1/alerts?tenant=acme&limit=10")
    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == 1
    assert rows[0]["tenant_id"] == "acme"
