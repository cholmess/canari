import canari


def test_threat_intel_local_feed(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))
    honey.alerter._channels = []
    t = honey.generate(n_tokens=1, token_types=["api_key"])[0]

    honey.scan_output(f"leak {t.value}", context={"conversation_id": "conv-ti"})
    honey.scan_output(f"leak {t.value}", context={"conversation_id": "conv-ti"})

    feed = honey.local_threat_feed(limit=100)
    assert feed["events_analyzed"] == 2
    assert feed["unique_signatures"] >= 1
    assert len(feed["signatures"]) >= 1
