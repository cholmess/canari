from canari.generator import CanaryGenerator
from canari.models import TokenType
from canari.registry import CanaryRegistry


def test_registry_stats(tmp_path):
    db = tmp_path / "canari.db"
    registry = CanaryRegistry(str(db))
    gen = CanaryGenerator()

    t1 = gen.generate(TokenType.API_KEY)
    t2 = gen.generate(TokenType.EMAIL)
    registry.add(t1)
    registry.add(t2)
    registry.deactivate(t2.id)

    stats = registry.stats()
    assert stats["total_tokens"] == 2
    assert stats["active_tokens"] == 1
    assert stats["inactive_tokens"] == 1
    assert stats["by_type"]["api_key"] == 1
    assert stats["by_type"]["email"] == 1
