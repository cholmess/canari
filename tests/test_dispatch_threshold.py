import canari


def test_dispatch_min_severity_filters_dispatch_only(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))
    honey.alerter._channels = []
    seen = []
    honey.alerter.add_callback(lambda e: seen.append(e.id))

    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]

    honey.set_min_dispatch_severity("high")
    # This should be low/medium depending on context; still stored, but not dispatched.
    honey.scan_output(f"leak {token.value}", context={"conversation_id": "conv-th"})

    assert len(seen) == 0
    assert len(honey.alert_history(limit=10)) == 1

    honey.clear_min_dispatch_severity()
    honey.scan_output(f"leak {token.value}", context={"conversation_id": "conv-th"})
    assert len(seen) == 1
