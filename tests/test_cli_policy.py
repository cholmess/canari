import json

from canari.cli import main


def test_cli_policy_set_and_show(tmp_path, capsys):
    db = tmp_path / "canari.db"

    rc = main(
        [
            "--db",
            str(db),
            "policy",
            "set",
            "--min-severity",
            "high",
            "--rate-window",
            "120",
            "--rate-max",
            "4",
            "--retention-days",
            "30",
        ]
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["saved"] is True

    rc = main(["--db", str(db), "policy", "show"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["min_dispatch_severity"] == "high"
    assert payload["rate_limit"]["window_seconds"] == 120
    assert payload["rate_limit"]["max_dispatches"] == 4
    assert payload["retention_days"] == 30

    rc = main(["--db", str(db), "apply-retention"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["applied"] is True
    assert payload["retention_days"] == 30
