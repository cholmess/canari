import canari


def test_client_alerter_health(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))
    honey.alerter._channels = []

    # no channels configured
    h = honey.alerter_health()
    assert h["channels"] == 0
    assert h["dispatch_successes"] == 0
    assert h["dispatch_failures"] == 0
