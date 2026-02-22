import canari


def test_audit_log_records_admin_actions(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))
    honey.alerter._channels = []
    honey.generate(n_tokens=1, token_types=["api_key"])

    honey.rotate_canaries(n_tokens=1, token_types=["api_key"])
    honey.purge_alerts_older_than(days=0)

    entries = honey.audit_log(limit=20)
    actions = {e["action"] for e in entries}
    assert "rotate_canaries" in actions
    assert "purge_alerts" in actions
