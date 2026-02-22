from __future__ import annotations

import hashlib
from collections import Counter

from canari.registry import CanaryRegistry


class ThreatIntelBuilder:
    def __init__(self, registry: CanaryRegistry):
        self.registry = registry

    def local_feed(self, limit: int = 5000) -> dict:
        alerts = self.registry.list_alerts(limit=limit)
        signatures = []
        counter = Counter()

        for a in alerts:
            raw = f"{a.token_type.value}|{a.detection_surface}|{a.severity.value}|{(a.output_snippet or '')[:120]}"
            sig = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
            counter[sig] += 1

        for sig, count in counter.most_common(50):
            sample = next(a for a in alerts if self._sig(a) == sig)
            signatures.append(
                {
                    "signature": sig,
                    "count": count,
                    "token_type": sample.token_type.value,
                    "surface": sample.detection_surface,
                    "severity": sample.severity.value,
                }
            )

        return {
            "events_analyzed": len(alerts),
            "unique_signatures": len(counter),
            "signatures": signatures,
        }

    @staticmethod
    def _sig(alert) -> str:
        raw = f"{alert.token_type.value}|{alert.detection_surface}|{alert.severity.value}|{(alert.output_snippet or '')[:120]}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
