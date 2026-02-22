import canari


def test_client_multisurface_sequence_escalates(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]

    out_events = honey.scan_output(
        f"leak {token.value}",
        context={"conversation_id": "conv-x", "session_metadata": {"source": "chat"}},
    )
    net_events = honey.monitor_http_request(
        "POST",
        "https://api.example.com/exfil",
        headers={"Authorization": f"Bearer {token.value}"},
        context={"conversation_id": "conv-x", "session_metadata": {"source": "egress"}},
    )

    assert len(out_events) == 1
    assert len(net_events) == 1
    assert out_events[0].correlation_count == 1
    assert net_events[0].correlation_count == 2
    assert net_events[0].severity.value == "critical"
    assert net_events[0].incident_id is not None


def test_recent_incidents_from_client(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))
    token = honey.generate(n_tokens=1, token_types=["email"])[0]
    honey.scan_output(f"show {token.value}", context={"conversation_id": "conv-y"})

    incidents = honey.recent_incidents(limit=10)
    assert len(incidents) == 1
    assert incidents[0].conversation_id == "conv-y"
