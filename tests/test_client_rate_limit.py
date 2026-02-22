import canari


def test_client_rate_limit_dispatch_only(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))
    honey.alerter._channels = []
    seen = []
    honey.alerter.add_callback(lambda e: seen.append(e.id))

    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]
    honey.set_alert_rate_limit(window_seconds=60, max_dispatches=1)

    honey.scan_output(f"leak {token.value}", context={"conversation_id": "conv-r1"})
    honey.scan_output(f"leak {token.value}", context={"conversation_id": "conv-r1"})

    # Only one dispatch, but both events should be stored.
    assert len(seen) == 1
    history = honey.alert_history(limit=10)
    assert len(history) == 2
