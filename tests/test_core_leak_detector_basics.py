import canari


def test_canary_generation_basics(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "core.db"))
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]

    assert token.token_type.value == "api_key"
    assert token.value.startswith("api_canari_")


def test_positive_detection_returns_alert(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "positive.db"))
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]

    alerts = honey.scan_output(f"leak {token.value}", context={"conversation_id": "core-pos"})

    assert len(alerts) == 1
    assert alerts[0].canary_value == token.value


def test_no_false_detection_on_clean_output(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "clean.db"))
    honey.generate(n_tokens=1, token_types=["api_key"])

    alerts = honey.scan_output("normal assistant response", context={"conversation_id": "core-clean"})

    assert alerts == []


def test_alert_trigger_callback_logic(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "callback.db"))
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]

    seen = []
    honey.alerter._channels = []
    honey.alerter.add_callback(lambda event: seen.append(event.id))

    alerts = honey.scan_output(f"exposed {token.value}", context={"conversation_id": "core-cb"})

    assert len(alerts) == 1
    assert len(seen) == 1
    assert seen[0] == alerts[0].id
