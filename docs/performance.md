# Performance

A smoke performance test exists in `tests/test_scanner_perf.py`.

Current threshold in CI-style local runs:

- output size: 10,000 chars
- active canaries: 50
- expected scan latency: < 20 ms

This is a conservative guardrail. When `pyahocorasick` is installed, scanner latency is typically lower than fallback substring matching.
