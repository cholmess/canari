import canari


def test_default_tenant_applies_when_missing(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))
    honey.alerter._channels = []
    honey.set_default_tenant("tenant-default")
    t = honey.generate(n_tokens=1, token_types=["api_key"])[0]

    events = honey.scan_output(f"leak {t.value}", context={"conversation_id": "conv-dt"})
    assert len(events) == 1
    assert events[0].tenant_id == "tenant-default"


def test_explicit_tenant_overrides_default(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))
    honey.alerter._channels = []
    honey.set_default_tenant("tenant-default")
    t = honey.generate(n_tokens=1, token_types=["api_key"])[0]

    events = honey.scan_output(
        f"leak {t.value}",
        context={"conversation_id": "conv-dt", "session_metadata": {"tenant_id": "tenant-explicit"}},
    )
    assert len(events) == 1
    assert events[0].tenant_id == "tenant-explicit"
