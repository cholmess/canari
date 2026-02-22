import canari
import pytest

pytest.importorskip("fastapi")
starlette_testclient = pytest.importorskip("starlette.testclient")

from canari.api import create_app


def test_fastapi_alerts_offset_limit(tmp_path):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    t = honey.generate(n_tokens=1, token_types=["api_key"])[0]
    for i in range(5):
        honey.scan_output(f"leak {t.value} {i}", context={"conversation_id": "conv-pg"})

    app = create_app(db_path=str(db), api_key=None)
    client = starlette_testclient.TestClient(app)

    r1 = client.get("/v1/alerts?limit=2&offset=0")
    r2 = client.get("/v1/alerts?limit=2&offset=2")
    assert r1.status_code == 200 and r2.status_code == 200
    assert len(r1.json()) == 2
    assert len(r2.json()) == 2
    assert r1.json()[0]["id"] != r2.json()[0]["id"]
