from __future__ import annotations

import hashlib
from datetime import datetime, timezone
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

    def export_share_bundle(self, limit: int = 5000) -> dict:
        return {
            "schema": "canari-threat-share-v1",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "opt_in_enabled": self.registry.threat_sharing_opt_in(),
            "feed": self.local_feed(limit=limit),
        }

    def import_share_bundle(self, payload: dict, *, source: str = "community") -> dict:
        signatures = payload.get("signatures")
        if signatures is None:
            signatures = payload.get("feed", {}).get("signatures", [])
        normalized = [
            {
                "signature": row.get("signature"),
                "count": row.get("count", 1),
                "token_type": row.get("token_type"),
                "surface": row.get("surface"),
                "severity": row.get("severity"),
            }
            for row in signatures
            if isinstance(row, dict)
        ]
        changed = self.registry.upsert_network_signatures(normalized, source=source)
        return {"imported": changed, "source": source}

    def network_signatures(self, *, limit: int = 500, offset: int = 0) -> list[dict]:
        return self.registry.list_network_signatures(limit=limit, offset=offset)

    def network_matches(self, *, local_limit: int = 5000, network_limit: int = 5000) -> dict:
        local = self.local_feed(limit=local_limit)
        network = self.registry.list_network_signatures(limit=network_limit)
        local_by_sig = {row["signature"]: row for row in local["signatures"]}
        matches = []
        for row in network:
            sig = row["signature"]
            local_row = local_by_sig.get(sig)
            if not local_row:
                continue
            matches.append(
                {
                    "signature": sig,
                    "local_count": int(local_row["count"]),
                    "network_count": int(row["count"]),
                    "token_type": local_row.get("token_type") or row.get("token_type"),
                    "surface": local_row.get("surface") or row.get("surface"),
                    "severity": local_row.get("severity") or row.get("severity"),
                    "source": row.get("source"),
                }
            )
        matches.sort(key=lambda m: (m["network_count"], m["local_count"]), reverse=True)
        return {
            "matches": matches,
            "match_count": len(matches),
            "local_unique_signatures": local.get("unique_signatures", 0),
            "network_signatures_considered": len(network),
        }

    def transparency_report(self, *, local_limit: int = 5000, network_limit: int = 5000) -> dict:
        local = self.local_feed(limit=local_limit)
        network = self.registry.list_network_signatures(limit=network_limit)
        matches = self.network_matches(local_limit=local_limit, network_limit=network_limit)
        by_source: dict[str, int] = {}
        for row in network:
            src = row.get("source") or "unknown"
            by_source[src] = by_source.get(src, 0) + 1
        return {
            "opt_in_enabled": self.registry.threat_sharing_opt_in(),
            "events_analyzed_local": local["events_analyzed"],
            "local_unique_signatures": local["unique_signatures"],
            "network_signatures_stored": len(network),
            "network_signature_sources": by_source,
            "network_match_count": matches["match_count"],
            "notes": [
                "Canari stores only anonymized signatures in the network catalog.",
                "Raw model outputs are not required for network matching.",
            ],
        }

    def attack_pattern_library(self, *, local_limit: int = 5000) -> dict:
        feed = self.local_feed(limit=local_limit)
        patterns = []
        for row in feed["signatures"]:
            patterns.append(
                {
                    "pattern_id": f"pat-{row['signature']}",
                    "signature": row["signature"],
                    "token_type": row.get("token_type"),
                    "surface": row.get("surface"),
                    "severity": row.get("severity"),
                    "observations": int(row.get("count", 0)),
                }
            )
        patterns.sort(key=lambda p: p["observations"], reverse=True)
        return {"patterns": patterns, "pattern_count": len(patterns)}

    @staticmethod
    def _sig(alert) -> str:
        raw = f"{alert.token_type.value}|{alert.detection_surface}|{alert.severity.value}|{(alert.output_snippet or '')[:120]}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
