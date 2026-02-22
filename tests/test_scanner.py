from canari.generator import CanaryGenerator
from canari.models import TokenType
from canari.registry import CanaryRegistry
from canari.scanner import OutputScanner


def test_scanner_finds_canary(tmp_path):
    db = tmp_path / "canari.db"
    registry = CanaryRegistry(str(db))
    token = CanaryGenerator().generate(TokenType.STRIPE_KEY)
    registry.add(token)

    scanner = OutputScanner(registry)
    events = scanner.scan(f"leaked: {token.value}", context={"conversation_id": "abc"})
    assert len(events) == 1
    assert events[0].canary_id == token.id
    assert events[0].conversation_id == "abc"


def test_scanner_clean_output(tmp_path):
    db = tmp_path / "canari.db"
    registry = CanaryRegistry(str(db))
    scanner = OutputScanner(registry)
    assert scanner.scan("safe output") == []
