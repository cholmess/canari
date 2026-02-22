from datetime import datetime, timezone

from canari.models import AlertEvent, AlertSeverity, InjectionStrategy, TokenType
from canari.registry import CanaryRegistry


def _evt(i: int, tenant: str) -> AlertEvent:
    now = datetime.now(timezone.utc)
    return AlertEvent(
        id=f"a-{i}",
        canary_id=f"c-{i}",
        canary_value=f"v-{i}",
        token_type=TokenType.API_KEY,
        injection_strategy=InjectionStrategy.CONTEXT_APPENDIX,
        injection_location="ctx",
        injected_at=now,
        severity=AlertSeverity.LOW,
        triggered_at=now,
        output_snippet="s",
        session_metadata={"tenant_id": tenant},
        tenant_id=tenant,
    )


def test_registry_tenant_filter(tmp_path):
    reg = CanaryRegistry(str(tmp_path / "canari.db"))
    reg.record_alert(_evt(1, "t1"))
    reg.record_alert(_evt(2, "t2"))

    alerts = reg.list_alerts(limit=10, tenant_id="t1")
    assert len(alerts) == 1
    assert alerts[0].tenant_id == "t1"
