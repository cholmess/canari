from canari.generator import CanaryGenerator
from canari.models import TokenType
from canari.registry import CanaryRegistry


def test_registry_add_and_get(tmp_path):
    db = tmp_path / "canari.db"
    registry = CanaryRegistry(str(db))
    token = CanaryGenerator().generate(TokenType.API_KEY)

    registry.add(token)

    by_id = registry.get_by_id(token.id)
    by_value = registry.get_by_value(token.value)
    assert by_id is not None
    assert by_value is not None
    assert by_id.id == token.id
    assert by_value.value == token.value


def test_registry_deactivate(tmp_path):
    db = tmp_path / "canari.db"
    registry = CanaryRegistry(str(db))
    token = CanaryGenerator().generate(TokenType.EMAIL)
    registry.add(token)

    assert registry.deactivate(token.id) is True
    assert registry.get_by_id(token.id).active is False
    assert registry.list_active() == []
