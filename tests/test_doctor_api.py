import canari


def test_client_doctor(tmp_path):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))

    report = honey.doctor()
    assert report["ok"] is True
    assert report["checks"]["tables"]["canary_tokens"] is True
    assert report["checks"]["tables"]["alert_events"] is True
