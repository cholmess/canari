import canari


def test_scoped_tokens_only_match_same_application(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))
    honey.alerter._channels = []

    token_a = honey.generate(n_tokens=1, token_types=["api_key"], application_id="app-a")[0]
    token_b = honey.generate(n_tokens=1, token_types=["api_key"], application_id="app-b")[0]

    events_a = honey.scan_output(
        f"leak {token_a.value} and {token_b.value}",
        context={"conversation_id": "conv-a", "session_metadata": {"application_id": "app-a"}},
    )
    assert len(events_a) == 1
    assert events_a[0].canary_value == token_a.value

    events_b = honey.scan_output(
        f"leak {token_a.value} and {token_b.value}",
        context={"conversation_id": "conv-b", "session_metadata": {"application_id": "app-b"}},
    )
    assert len(events_b) == 1
    assert events_b[0].canary_value == token_b.value


def test_unscoped_tokens_match_any_application(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))
    honey.alerter._channels = []
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]

    events = honey.scan_output(
        f"leak {token.value}",
        context={"conversation_id": "conv-any", "session_metadata": {"application_id": "app-x"}},
    )
    assert len(events) == 1
    assert events[0].canary_value == token.value
