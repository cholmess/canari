from __future__ import annotations

from dataclasses import dataclass

from canari.models import AlertSeverity, CanaryToken, TokenType

_EXFIL_KEYWORDS = (
    "ignore previous instructions",
    "repeat all documents",
    "verbatim",
    "dump",
    "exfiltrate",
    "show hidden prompt",
    "output everything",
    "reveal secrets",
)


@dataclass
class DetectionAssessment:
    severity: AlertSeverity
    reason: str


class ExfiltrationAnalyzer:
    def assess(self, token: CanaryToken, output: str, hit_count: int) -> DetectionAssessment:
        lowered = output.lower()
        keyword_hits = sum(1 for kw in _EXFIL_KEYWORDS if kw in lowered)
        sensitive = token.token_type in {TokenType.AWS_KEY, TokenType.STRIPE_KEY, TokenType.GITHUB_TOKEN}

        if keyword_hits >= 2 and (sensitive or hit_count >= 2):
            return DetectionAssessment(
                severity=AlertSeverity.CRITICAL,
                reason="active exfiltration pattern keywords present with sensitive leak",
            )
        if sensitive:
            return DetectionAssessment(
                severity=AlertSeverity.HIGH,
                reason="sensitive credential token leaked",
            )
        if hit_count > 1:
            return DetectionAssessment(
                severity=AlertSeverity.MEDIUM,
                reason="multiple canary tokens leaked in same output",
            )
        return DetectionAssessment(
            severity=AlertSeverity.LOW,
            reason="single canary token leaked",
        )
