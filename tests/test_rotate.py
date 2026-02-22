import canari


def test_rotate_canaries_deactivates_and_reseeds(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))
    initial = honey.generate(n_tokens=3, token_types=["api_key", "email"])

    report = honey.rotate_canaries(n_tokens=2, token_types=["api_key"])
    assert report["deactivated"] == 3
    assert report["generated"] == 2

    stats = honey.registry_stats()
    assert stats["active_tokens"] == 2
    assert stats["inactive_tokens"] == 3

    old_ids = {t.id for t in initial}
    active_ids = {t.id for t in honey.registry.list_active()}
    assert old_ids.isdisjoint(active_ids)
