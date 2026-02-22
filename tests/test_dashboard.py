import json
from urllib.request import urlopen

import canari
import pytest
from canari.dashboard import DashboardServer


def test_dashboard_server_endpoints(tmp_path):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]
    honey.scan_output(
        f"leak {token.value}",
        context={
            "conversation_id": "conv-dash",
            "session_metadata": {"application_id": "dash-app", "tenant_id": "acme"},
        },
    )

    srv = DashboardServer(db_path=str(db), host="127.0.0.1", port=0)
    try:
        host, port = srv.start()
    except PermissionError:
        pytest.skip("socket bind not permitted in sandbox")
    try:
        with urlopen(f"http://{host}:{port}/api/health") as r:
            health = json.loads(r.read().decode("utf-8"))
        assert health["ok"] is True

        with urlopen(f"http://{host}:{port}/api/summary?limit=100") as r:
            summary = json.loads(r.read().decode("utf-8"))
        assert summary["alerts"]["total_alerts"] >= 1
        with urlopen(f"http://{host}:{port}/api/summary?limit=100&app=dash-app") as r:
            app_summary = json.loads(r.read().decode("utf-8"))
        assert app_summary["alerts"]["total_alerts"] >= 1
        with urlopen(f"http://{host}:{port}/api/summary?limit=100&tenant=acme&app=dash-app") as r:
            scoped_summary = json.loads(r.read().decode("utf-8"))
        assert scoped_summary["alerts"]["total_alerts"] >= 1

        with urlopen(f"http://{host}:{port}/api/alerts?limit=10") as r:
            alerts = json.loads(r.read().decode("utf-8"))
        assert len(alerts) == 1
        with urlopen(f"http://{host}:{port}/api/alerts?limit=10&app=dash-app") as r:
            app_alerts = json.loads(r.read().decode("utf-8"))
        assert len(app_alerts) == 1
        with urlopen(f"http://{host}:{port}/api/incidents?limit=10&tenant=acme&app=dash-app") as r:
            incidents = json.loads(r.read().decode("utf-8"))
        assert len(incidents) == 1

        with urlopen(f"http://{host}:{port}/") as r:
            html = r.read().decode("utf-8")
        assert "Canari Dashboard" in html
    finally:
        srv.stop()
