from datetime import datetime, timezone

from canari.incidents import IncidentManager
from canari.models import AlertEvent, AlertSeverity, InjectionStrategy, TokenType


def _event(surface: str, conv: str, sev: AlertSeverity, idx: int) -> AlertEvent:
    now = datetime.now(timezone.utc)
    return AlertEvent(
        id=f"a-{idx}",
        canary_id=f"c-{idx}",
        canary_value=f"v-{idx}",
        token_type=TokenType.API_KEY,
        injection_strategy=InjectionStrategy.CONTEXT_APPENDIX,
        injection_location="ctx",
        injected_at=now,
        severity=sev,
        triggered_at=now,
        conversation_id=conv,
        output_snippet="snippet",
        detection_surface=surface,
    )


def test_multisurface_correlation_escalates_to_critical():
    mgr = IncidentManager(window_seconds=600)
    first = mgr.correlate(_event("output", "conv-1", AlertSeverity.LOW, 1))
    second = mgr.correlate(_event("network_egress", "conv-1", AlertSeverity.HIGH, 2))

    assert first.correlation_count == 1
    assert second.correlation_count == 2
    assert second.severity == AlertSeverity.CRITICAL
    assert second.incident_id is not None


def test_recent_incidents_snapshot():
    mgr = IncidentManager(window_seconds=600)
    mgr.correlate(_event("output", "conv-2", AlertSeverity.LOW, 1))
    snapshots = mgr.recent_incidents(limit=10)

    assert len(snapshots) == 1
    assert snapshots[0].conversation_id == "conv-2"
    assert snapshots[0].event_count == 1
