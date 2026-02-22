import time

from canari.generator import CanaryGenerator
from canari.models import TokenType
from canari.registry import CanaryRegistry
from canari.scanner import OutputScanner


def test_scanner_performance_smoke(tmp_path):
    registry = CanaryRegistry(str(tmp_path / "canari.db"))
    gen = CanaryGenerator()
    for _ in range(50):
        registry.add(gen.generate(TokenType.API_KEY))

    scanner = OutputScanner(registry)
    output = "x" * 10000

    start = time.perf_counter()
    events = scanner.scan(output)
    elapsed = time.perf_counter() - start

    assert events == []
    assert elapsed < 0.02
