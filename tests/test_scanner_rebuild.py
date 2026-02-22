from canari.generator import CanaryGenerator
from canari.models import TokenType
from canari.registry import CanaryRegistry
from canari.scanner import OutputScanner


def test_scanner_auto_rebuild_on_registry_change(tmp_path):
    reg = CanaryRegistry(str(tmp_path / "canari.db"))
    scanner = OutputScanner(reg)

    gen = CanaryGenerator()
    token = gen.generate(TokenType.API_KEY)
    reg.add(token)

    # scanner was created before token add; should auto-rebuild and find it.
    events = scanner.scan(f"leak {token.value}")
    assert len(events) == 1

    reg.deactivate(token.id)
    # scanner should auto-rebuild again and stop matching.
    events = scanner.scan(f"leak {token.value}")
    assert len(events) == 0
