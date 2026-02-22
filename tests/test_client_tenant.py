import canari


def test_client_tenant_propagation_and_filter(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))
    honey.alerter._channels = []
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]

    honey.scan_output(
        f"leak {token.value}",
        context={"conversation_id": "conv-t", "session_metadata": {"tenant_id": "acme"}},
    )

    alerts = honey.alert_history(limit=10, tenant_id="acme")
    assert len(alerts) == 1
    assert alerts[0].tenant_id == "acme"
