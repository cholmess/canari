import canari


def test_settings_persist_and_reload(tmp_path):
    db = tmp_path / "canari.db"

    c1 = canari.init(db_path=str(db))
    c1.alerter._channels = []
    c1.set_alert_rate_limit(window_seconds=99, max_dispatches=2)
    c1.set_min_dispatch_severity("high")
    c1.persist_policy()

    c2 = canari.init(db_path=str(db))
    c2.alerter._channels = []
    # should autoload persisted policy
    assert c2.min_dispatch_severity == "high"
    assert c2.rate_limiter is not None
    assert c2.rate_limiter.window.total_seconds() == 99
    assert c2.rate_limiter.max_dispatches == 2
