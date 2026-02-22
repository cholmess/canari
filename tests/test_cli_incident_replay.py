import json

import canari
from canari.cli import main


def test_cli_incident_replay_jsonl(tmp_path, capsys):
    db = tmp_path / "canari.db"
    out = tmp_path / "incident.jsonl"

    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]
    events = honey.scan_output(f"leak {token.value}", context={"conversation_id": "conv-replay"})
    incident_id = events[0].incident_id

    rc = main(
        [
            "--db",
            str(db),
            "incident-replay",
            "--incident",
            incident_id,
            "--out",
            str(out),
        ]
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["written"] == 1
    assert out.exists()
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
