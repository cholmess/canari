import canari


def test_api_key_rotation(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))

    created = honey.create_api_key(name="ops", key="old-secret", role="admin")
    rotated = honey.rotate_api_key(key_id=created["id"], new_key="new-secret")

    assert rotated["old_key_revoked"] is True
    assert rotated["new_key"]["id"] != created["id"]

    keys = honey.list_api_keys()
    assert len(keys) == 2
    old = [k for k in keys if k["id"] == created["id"]][0]
    assert old["active"] is False
