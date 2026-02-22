import sqlite3

import canari


def test_backup_db_contains_tables(tmp_path):
    db = tmp_path / "canari.db"
    backup = tmp_path / "backup.db"

    honey = canari.init(db_path=str(db))
    honey.alerter._channels = []
    honey.generate(n_tokens=1, token_types=["api_key"])

    bytes_written = honey.backup_db(str(backup))
    assert bytes_written > 0
    assert backup.exists()

    with sqlite3.connect(str(backup)) as conn:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        names = {r[0] for r in rows}

    assert "canary_tokens" in names
    assert "alert_events" in names
