import canari


def test_client_registry_stats(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))
    honey.generate(n_tokens=3, token_types=["api_key", "email"])

    stats = honey.registry_stats()
    assert stats["total_tokens"] == 3
    assert stats["active_tokens"] == 3
