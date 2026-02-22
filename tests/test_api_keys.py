import canari


def test_api_key_lifecycle(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))

    key = honey.create_api_key(name="ci", key="secret-ci", role="reader")
    assert key["name"] == "ci"
    assert key["active"] is True

    keys = honey.list_api_keys()
    assert len(keys) == 1
    assert keys[0]["name"] == "ci"
    assert keys[0]["role"] == "reader"

    revoked = honey.revoke_api_key(key["id"])
    assert revoked is True
    keys = honey.list_api_keys()
    assert keys[0]["active"] is False
