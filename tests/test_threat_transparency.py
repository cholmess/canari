import json

import canari
import pytest
from canari.cli import main

pytest.importorskip("fastapi")
starlette_testclient = pytest.importorskip("starlette.testclient")

from canari.api import create_app


def test_cli_transparency_and_patterns(tmp_path, capsys):
    db = tmp_path / "canari.db"
    out_tr = tmp_path / "transparency.json"
    out_pat = tmp_path / "patterns.json"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]
    honey.scan_output(f"leak {token.value}", context={"conversation_id": "conv-tr"})

    assert main(["--db", str(db), "threat-transparency", "--local-limit", "100", "--network-limit", "100"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert "opt_in_enabled" in report
    assert "network_match_count" in report

    assert main(["--db", str(db), "attack-patterns", "--local-limit", "100"]) == 0
    patterns = json.loads(capsys.readouterr().out)
    assert patterns["pattern_count"] >= 1

    assert (
        main(
            [
                "--db",
                str(db),
                "threat-transparency",
                "--local-limit",
                "100",
                "--network-limit",
                "100",
                "--out",
                str(out_tr),
            ]
        )
        == 0
    )
    write_tr = json.loads(capsys.readouterr().out)
    assert write_tr["written"] is True
    assert out_tr.exists()

    assert main(["--db", str(db), "attack-patterns", "--local-limit", "100", "--out", str(out_pat)]) == 0
    write_pat = json.loads(capsys.readouterr().out)
    assert write_pat["written"] is True
    assert out_pat.exists()


def test_fastapi_transparency_and_patterns(tmp_path):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    honey.create_api_key(name="admin", key="admin-key", role="admin")

    app = create_app(db_path=str(db), api_key=None)
    client = starlette_testclient.TestClient(app)

    r = client.get("/v1/threat-transparency?local_limit=100&network_limit=100", headers={"X-API-Key": "admin-key"})
    assert r.status_code == 200
    assert "opt_in_enabled" in r.json()

    r = client.get("/v1/attack-patterns?local_limit=100", headers={"X-API-Key": "admin-key"})
    assert r.status_code == 200
    assert "pattern_count" in r.json()
