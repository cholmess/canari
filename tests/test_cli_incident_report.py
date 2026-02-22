import json

import canari
from canari.cli import main


def test_cli_incident_report_scoped_app(tmp_path, capsys):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []

    token = honey.generate(n_tokens=1, token_types=["api_key"], application_id="support-app")[0]
    events = honey.scan_output(
        f"leak {token.value}",
        context={"conversation_id": "conv-cli-ir", "session_metadata": {"application_id": "support-app"}},
    )
    incident_id = events[0].incident_id

    rc = main(["--db", str(db), "incident-report", incident_id, "--app", "support-app"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["found"] is True
