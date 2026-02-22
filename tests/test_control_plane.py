import json

import canari
import pytest
from canari.cli import main

pytest.importorskip("fastapi")
starlette_testclient = pytest.importorskip("starlette.testclient")

from canari.api import create_app


def test_client_control_plane_export_import(tmp_path):
    src_db = tmp_path / "src.db"
    dst_db = tmp_path / "dst.db"
    src = canari.init(db_path=str(src_db))
    src.alerter._channels = []
    src.set_min_dispatch_severity("high")
    src.set_retention_policy(30)
    src.persist_policy()
    src.set_scoped_retention_policy(retention_days=14, tenant_id="acme", application_id="app-a")
    src.registry.upsert_network_signatures(
        [{"signature": "abc123def4567890", "count": 2, "token_type": "api_key", "severity": "high"}],
        source="test",
    )

    bundle = src.export_control_plane_bundle()
    valid = src.validate_control_plane_bundle(bundle)
    assert valid["ok"] is True
    assert bundle["schema"] == "canari-control-plane-v1"
    assert bundle["schema_version"] == 1
    assert len(bundle["retention_policies"]) >= 1
    assert len(bundle["network_signatures"]) >= 1

    dst = canari.init(db_path=str(dst_db))
    dst.alerter._channels = []
    out = dst.import_control_plane_bundle(bundle, source="test-import")
    assert out["settings_applied"] >= 1
    assert out["retention_policies_applied"] >= 1
    assert out["network_signatures_imported"] >= 1

    dst2 = canari.init(db_path=str(tmp_path / "dst2.db"))
    dst2.alerter._channels = []
    dry = dst2.import_control_plane_bundle(bundle, source="test-import", dry_run=True)
    assert dry["dry_run"] is True
    assert dst2.scoped_retention_policies() == []


def test_cli_control_plane_export_import(tmp_path, capsys):
    src_db = tmp_path / "src.db"
    dst_db = tmp_path / "dst.db"
    out_file = tmp_path / "cp.json"

    src = canari.init(db_path=str(src_db))
    src.alerter._channels = []
    src.set_scoped_retention_policy(retention_days=21, application_id="ops")
    src.registry.upsert_network_signatures(
        [{"signature": "1234abcd5678ef00", "count": 1, "token_type": "api_key", "severity": "medium"}],
        source="test",
    )

    assert main(["--db", str(src_db), "control-plane-export", "--out", str(out_file)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["written"] is True
    assert out_file.exists()
    assert main(["--db", str(src_db), "control-plane-validate", "--in", str(out_file)]) == 0
    validate = json.loads(capsys.readouterr().out)
    assert validate["ok"] is True

    assert main(["--db", str(dst_db), "control-plane-import", "--in", str(out_file), "--source", "cli"]) == 0
    imported = json.loads(capsys.readouterr().out)
    assert imported["retention_policies_applied"] >= 1

    dst_dry = tmp_path / "dst_dry.db"
    assert (
        main(
            [
                "--db",
                str(dst_dry),
                "control-plane-import",
                "--in",
                str(out_file),
                "--source",
                "cli",
                "--dry-run",
            ]
        )
        == 0
    )
    dry = json.loads(capsys.readouterr().out)
    assert dry["dry_run"] is True


def test_fastapi_control_plane_export_import(tmp_path):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    honey.create_api_key(name="admin", key="admin-key", role="admin")

    app = create_app(db_path=str(db), api_key=None)
    client = starlette_testclient.TestClient(app)

    r = client.get("/v1/control-plane/export", headers={"X-API-Key": "admin-key"})
    assert r.status_code == 200
    bundle = r.json()
    assert bundle["schema"] == "canari-control-plane-v1"
    assert bundle["schema_version"] == 1

    r = client.post(
        "/v1/control-plane/import",
        headers={"X-API-Key": "admin-key"},
        json={
            "source": "api-test",
            "settings": {"policy.min_dispatch_severity": "medium"},
            "retention_policies": [{"retention_days": 14, "tenant_id": "acme", "application_id": "app-a"}],
            "network_signatures": [{"signature": "a1b2c3d4e5f60708", "count": 1, "severity": "low"}],
            "api_keys_metadata": [],
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["settings_applied"] >= 1
    assert body["retention_policies_applied"] >= 1

    r = client.post(
        "/v1/control-plane/import?dry_run=true",
        headers={"X-API-Key": "admin-key"},
        json={
            "source": "api-test",
            "settings": {"policy.min_dispatch_severity": "high"},
            "retention_policies": [{"retention_days": 30, "application_id": "app-z"}],
            "network_signatures": [{"signature": "0011223344556677", "count": 1, "severity": "low"}],
            "api_keys_metadata": [],
        },
    )
    assert r.status_code == 200
    assert r.json()["dry_run"] is True

    r = client.post(
        "/v1/control-plane/validate",
        headers={"X-API-Key": "admin-key"},
        json={"schema": "canari-control-plane-v1", "settings": {}, "retention_policies": [], "network_signatures": []},
    )
    assert r.status_code == 200
    assert r.json()["ok"] is True
