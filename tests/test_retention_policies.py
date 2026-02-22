import json
from datetime import datetime, timedelta, timezone

import canari
import pytest
from canari.cli import main
from canari.models import AlertEvent, AlertSeverity, InjectionStrategy, TokenType

pytest.importorskip("fastapi")
starlette_testclient = pytest.importorskip("starlette.testclient")

from canari.api import create_app


def _old_event(alert_id: str, app: str) -> AlertEvent:
    now = datetime.now(timezone.utc)
    return AlertEvent(
        id=alert_id,
        canary_id="cid",
        canary_value=f"v-{alert_id}",
        token_type=TokenType.API_KEY,
        injection_strategy=InjectionStrategy.CONTEXT_APPENDIX,
        injection_location="ctx",
        injected_at=now - timedelta(days=20),
        severity=AlertSeverity.LOW,
        triggered_at=now - timedelta(days=20),
        output_snippet="s",
        application_id=app,
    )


def test_cli_scoped_retention_policy(tmp_path, capsys):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    honey.registry.record_alert(_old_event("old-a", "app-a"))
    honey.registry.record_alert(_old_event("old-b", "app-b"))

    assert main(["--db", str(db), "retention-policy", "set", "--retention-days", "7", "--app", "app-a"]) == 0
    set_payload = json.loads(capsys.readouterr().out)
    assert set_payload["application_id"] == "app-a"

    assert main(["--db", str(db), "retention-policy", "apply"]) == 0
    apply_payload = json.loads(capsys.readouterr().out)
    assert apply_payload["policies_applied"] >= 1

    remaining = honey.alert_history(limit=10)
    ids = {e.id for e in remaining}
    assert "old-a" not in ids
    assert "old-b" in ids


def test_fastapi_retention_policy_endpoints(tmp_path):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    honey.create_api_key(name="admin", key="admin-key", role="admin")

    app = create_app(db_path=str(db), api_key=None)
    client = starlette_testclient.TestClient(app)

    r = client.post(
        "/v1/retention-policies",
        headers={"X-API-Key": "admin-key"},
        json={"retention_days": 14, "application_id": "app-z"},
    )
    assert r.status_code == 200
    assert r.json()["application_id"] == "app-z"

    r = client.get("/v1/retention-policies", headers={"X-API-Key": "admin-key"})
    assert r.status_code == 200
    assert len(r.json()) >= 1

    r = client.post("/v1/retention-policies/apply", headers={"X-API-Key": "admin-key"})
    assert r.status_code == 200
    assert "policies_applied" in r.json()
