import json

import canari
from canari.cli import main


def test_cli_stats_and_export(tmp_path, capsys):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]
    honey.scan_output(f"leak {token.value}", context={"conversation_id": "conv-cli"})

    rc = main(["--db", str(db), "token-stats"])
    assert rc == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["total_tokens"] == 1

    out_file = tmp_path / "alerts.jsonl"
    rc = main(["--db", str(db), "export", "--format", "jsonl", "--out", str(out_file)])
    assert rc == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["exported"] == 1
    assert out_file.exists()


def test_cli_forensic_summary_and_alert_incident_filter(tmp_path, capsys):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]
    events = honey.scan_output(f"leak {token.value}", context={"conversation_id": "conv-cli-2"})
    incident_id = events[0].incident_id

    rc = main(["--db", str(db), "forensic-summary", "--limit", "100"])
    assert rc == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["alerts"]["total_alerts"] >= 1

    rc = main(["--db", str(db), "alerts", "--incident", incident_id, "--limit", "10"])
    assert rc == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert len(payload) == 1


def test_cli_seed_and_scan_text(tmp_path, capsys):
    db = tmp_path / "canari.db"

    rc = main(["--db", str(db), "seed", "--n", "2", "--types", "api_key,email"])
    assert rc == 0
    out = capsys.readouterr().out
    tokens = json.loads(out)
    assert len(tokens) == 2

    leaked = tokens[0]["value"]
    rc = main(
        [
            "--db",
            str(db),
            "scan-text",
            "--text",
            f"leak {leaked}",
            "--conversation",
            "conv-cli-scan",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    events = json.loads(out)
    assert len(events) == 1
    assert events[0]["conversation_id"] == "conv-cli-scan"
