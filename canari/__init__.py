import asyncio

from canari.adapters import patch_openai_client, wrap_runnable
from canari.alerter import AlertDispatcher
from canari.generator import CanaryGenerator
from canari.incidents import IncidentManager
from canari.integrations import inject_canaries_into_index, wrap_chain, wrap_query_engine
from canari.injector import inject_as_document, inject_into_system_prompt, wrap_context_assembler
from canari.dashboard import DashboardServer
from canari.monitor import EgressMonitor
from canari.models import AlertEvent, CanaryToken, InjectionStrategy, TokenType
from canari.rate_limit import AlertRateLimiter
from canari.exporter import AlertExporter
from canari.reporting import ForensicReporter
from canari.threat_intel import ThreatIntelBuilder
from canari.registry import CanaryRegistry
from canari.scanner import OutputScanner

__version__ = "0.1.0"


class CanariClient:
    def __init__(self, db_path: str = "canari.db"):
        self.registry = CanaryRegistry(db_path=db_path)
        self.generator = CanaryGenerator()
        self.scanner = OutputScanner(self.registry)
        self.egress_monitor = EgressMonitor(self.registry)
        self.incidents = IncidentManager()
        self.reporter = ForensicReporter(self.registry)
        self.exporter = AlertExporter(self.registry)
        self.threat_intel = ThreatIntelBuilder(self.registry)
        self.rate_limiter: AlertRateLimiter | None = None
        self.min_dispatch_severity: str | None = None
        self.retention_days: int | None = None
        self.default_tenant_id: str | None = None
        self.default_application_id: str | None = None
        self.alerter = AlertDispatcher(canari_version=__version__)
        self.alerter.add_stdout()
        self.load_policy()

    def generate(
        self,
        n_tokens: int = 1,
        token_types: list[str] | None = None,
        *,
        tenant_id: str | None = None,
        application_id: str | None = None,
    ) -> list[CanaryToken]:
        kinds = token_types or [TokenType.API_KEY.value]
        selected = [TokenType(k) for k in kinds]
        tokens = []
        for i in range(n_tokens):
            token_type = selected[i % len(selected)]
            token = self.generator.generate(
                token_type,
                tenant_id=tenant_id,
                application_id=application_id,
            )
            self.registry.add(token)
            tokens.append(token)
        self.scanner._rebuild_index()
        return tokens

    def rotate_canaries(
        self,
        n_tokens: int = 3,
        token_types: list[str] | None = None,
        *,
        tenant_id: str | None = None,
        application_id: str | None = None,
    ) -> dict:
        active = self.registry.list_active()
        deactivated = 0
        for token in active:
            if self.registry.deactivate(token.id):
                deactivated += 1
        self.scanner._rebuild_index()
        generated = self.generate(
            n_tokens=n_tokens,
            token_types=token_types,
            tenant_id=tenant_id,
            application_id=application_id,
        )
        report = {
            "deactivated": deactivated,
            "generated": len(generated),
            "active_now": len(self.registry.list_active()),
        }
        self.registry.record_audit(
            "rotate_canaries",
            report
            | {
                "token_types": token_types or ["api_key"],
                "tenant_id": tenant_id,
                "application_id": application_id,
            },
        )
        return report

    def inject_system_prompt(self, system_prompt: str, canaries: list[CanaryToken], position: str = "end") -> str:
        return inject_into_system_prompt(system_prompt, canaries, position=position)

    def wrap_context_assembler(self, assembler_fn, canaries: list[CanaryToken], appendix_format: str = "hidden"):
        return wrap_context_assembler(assembler_fn, canaries, appendix_format=appendix_format)

    def inject_vectorstore(self, vector_store, n_tokens: int = 3, token_types: list[str] | None = None) -> list[str]:
        canaries = self.generate(n_tokens=n_tokens, token_types=token_types)
        doc_ids = []
        for canary in canaries:
            doc_ids.append(inject_as_document(vector_store, canary))
        return doc_ids

    def inject_index(self, index, n_tokens: int = 3, token_types: list[str] | None = None) -> list[str]:
        canaries = self.generate(n_tokens=n_tokens, token_types=token_types)
        return inject_canaries_into_index(index, canaries)

    def wrap_llm_call(self, llm_fn):
        if asyncio.iscoroutinefunction(llm_fn):
            async def async_wrapped(*args, **kwargs):
                result = await llm_fn(*args, **kwargs)
                output = self.scanner._extract_text(result)
                self.scan_output(output, context=self._context_from_llm_call(args, kwargs))
                return result

            return async_wrapped

        def wrapped(*args, **kwargs):
            result = llm_fn(*args, **kwargs)
            output = self.scanner._extract_text(result)
            self.scan_output(output, context=self._context_from_llm_call(args, kwargs))
            return result

        return wrapped

    def wrap_chain(self, chain):
        return wrap_chain(chain, self.scan_output)

    def wrap_query_engine(self, query_engine):
        return wrap_query_engine(query_engine, self.scan_output)

    def wrap_runnable(self, runnable):
        return wrap_runnable(runnable, self.scan_output)

    def patch_openai_client(self, client):
        return patch_openai_client(client, self.wrap_llm_call)

    def scan_output(self, output: str, context: dict | None = None) -> list[AlertEvent]:
        context = self._with_default_tenant(context)
        events = self.scanner.scan(output, context=context)
        correlated_events = []
        for event in events:
            correlated = self.incidents.correlate(event)
            correlated_events.append(correlated)
            self.registry.record_alert(correlated)
            if self._should_dispatch(correlated):
                self.alerter.dispatch(correlated)
            self._dispatch_network_match_if_opted_in(correlated)
        return correlated_events

    def monitor_http_request(
        self,
        method: str,
        url: str,
        *,
        headers: dict | None = None,
        body=None,
        context: dict | None = None,
    ) -> list[AlertEvent]:
        context = self._with_default_tenant(context)
        events = self.egress_monitor.inspect_http_request(
            method,
            url,
            headers=headers,
            body=body,
            context=context,
        )
        correlated_events = []
        for event in events:
            correlated = self.incidents.correlate(event)
            correlated_events.append(correlated)
            self.registry.record_alert(correlated)
            if self._should_dispatch(correlated):
                self.alerter.dispatch(correlated)
            self._dispatch_network_match_if_opted_in(correlated)
        return correlated_events

    def wrap_httpx_client(self, client):
        if not hasattr(client, "request"):
            raise TypeError("client must expose request(method, url, **kwargs)")
        original_request = client.request

        if asyncio.iscoroutinefunction(original_request):
            async def wrapped_request(method, url, **kwargs):
                headers = kwargs.get("headers")
                body = kwargs.get("json", kwargs.get("data"))
                self.monitor_http_request(method, url, headers=headers, body=body)
                return await original_request(method, url, **kwargs)

            client.request = wrapped_request
        else:
            def wrapped_request(method, url, **kwargs):
                headers = kwargs.get("headers")
                body = kwargs.get("json", kwargs.get("data"))
                self.monitor_http_request(method, url, headers=headers, body=body)
                return original_request(method, url, **kwargs)

            client.request = wrapped_request
        return client

    def registry_stats(self) -> dict:
        return self.registry.stats()

    def alert_history(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        severity: str | None = None,
        detection_surface: str | None = None,
        conversation_id: str | None = None,
        incident_id: str | None = None,
        since: str | None = None,
        until: str | None = None,
        tenant_id: str | None = None,
        application_id: str | None = None,
    ):
        return self.registry.list_alerts(
            limit=limit,
            offset=offset,
            severity=severity,
            detection_surface=detection_surface,
            conversation_id=conversation_id,
            incident_id=incident_id,
            since=since,
            until=until,
            tenant_id=tenant_id,
            application_id=application_id,
        )

    def alert_stats(self, *, tenant_id: str | None = None, application_id: str | None = None) -> dict:
        return self.registry.alert_stats(tenant_id=tenant_id, application_id=application_id)

    def purge_alerts_older_than(
        self,
        *,
        days: int,
        tenant_id: str | None = None,
        application_id: str | None = None,
    ) -> int:
        removed = self.registry.purge_alerts_older_than(
            days=days,
            tenant_id=tenant_id,
            application_id=application_id,
        )
        self.registry.record_audit(
            "purge_alerts",
            {
                "days": days,
                "removed": removed,
                "tenant_id": tenant_id,
                "application_id": application_id,
            },
        )
        return removed

    def backup_db(self, path: str) -> int:
        size = self.registry.backup_to(path)
        self.registry.record_audit("backup_db", {"path": path, "bytes": size})
        return size

    def doctor(self) -> dict:
        return self.registry.doctor()

    def alerter_health(self) -> dict:
        return self.alerter.health()

    def create_dashboard_server(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        api_token: str | None = None,
    ) -> DashboardServer:
        return DashboardServer(db_path=self.registry.db_path, host=host, port=port, api_token=api_token)

    def create_fastapi_app(self, api_key: str | None = None):
        from canari.api import create_app

        return create_app(db_path=self.registry.db_path, api_key=api_key)

    def set_alert_rate_limit(self, *, window_seconds: int = 60, max_dispatches: int = 3) -> None:
        self.rate_limiter = AlertRateLimiter(window_seconds=window_seconds, max_dispatches=max_dispatches)

    def disable_alert_rate_limit(self) -> None:
        self.rate_limiter = None

    def set_min_dispatch_severity(self, severity: str) -> None:
        valid = {"low", "medium", "high", "critical"}
        normalized = severity.lower()
        if normalized not in valid:
            raise ValueError(f"severity must be one of {sorted(valid)}")
        self.min_dispatch_severity = normalized

    def clear_min_dispatch_severity(self) -> None:
        self.min_dispatch_severity = None

    def set_default_tenant(self, tenant_id: str) -> None:
        self.default_tenant_id = tenant_id

    def clear_default_tenant(self) -> None:
        self.default_tenant_id = None

    def set_default_application(self, application_id: str) -> None:
        self.default_application_id = application_id

    def clear_default_application(self) -> None:
        self.default_application_id = None

    def persist_policy(self) -> None:
        if self.min_dispatch_severity is None:
            self.registry.set_setting("policy.min_dispatch_severity", "")
        else:
            self.registry.set_setting("policy.min_dispatch_severity", self.min_dispatch_severity)

        if self.rate_limiter is None:
            self.registry.set_setting("policy.rate_window_seconds", "")
            self.registry.set_setting("policy.rate_max_dispatches", "")
        else:
            self.registry.set_setting(
                "policy.rate_window_seconds",
                str(int(self.rate_limiter.window.total_seconds())),
            )
            self.registry.set_setting("policy.rate_max_dispatches", str(self.rate_limiter.max_dispatches))
        self.registry.set_setting(
            "policy.retention_days",
            "" if self.retention_days is None else str(int(self.retention_days)),
        )
        self.registry.record_audit("persist_policy", self.policy())

    def load_policy(self) -> None:
        min_sev = self.registry.get_setting("policy.min_dispatch_severity")
        if min_sev:
            self.set_min_dispatch_severity(min_sev)
        else:
            self.clear_min_dispatch_severity()

        win = self.registry.get_setting("policy.rate_window_seconds")
        mx = self.registry.get_setting("policy.rate_max_dispatches")
        if win and mx:
            try:
                self.set_alert_rate_limit(window_seconds=int(win), max_dispatches=int(mx))
            except Exception:
                self.disable_alert_rate_limit()
        else:
            self.disable_alert_rate_limit()
        retention = self.registry.get_setting("policy.retention_days")
        if retention:
            try:
                self.retention_days = int(retention)
            except Exception:
                self.retention_days = None
        else:
            self.retention_days = None

    def policy(self) -> dict:
        out = {
            "min_dispatch_severity": self.min_dispatch_severity,
            "rate_limit": None,
        }
        if self.rate_limiter is not None:
            out["rate_limit"] = {
                "window_seconds": int(self.rate_limiter.window.total_seconds()),
                "max_dispatches": self.rate_limiter.max_dispatches,
            }
        out["retention_days"] = self.retention_days
        return out

    def set_retention_policy(self, days: int | None) -> None:
        if days is None:
            self.retention_days = None
            return
        n = int(days)
        if n <= 0:
            raise ValueError("retention days must be > 0")
        self.retention_days = n

    def apply_retention_policy(
        self,
        *,
        tenant_id: str | None = None,
        application_id: str | None = None,
    ) -> dict:
        if self.retention_days is None:
            return {"applied": False, "removed": 0, "retention_days": None}
        removed = self.purge_alerts_older_than(
            days=self.retention_days,
            tenant_id=tenant_id,
            application_id=application_id,
        )
        self.registry.record_audit(
            "apply_retention_policy",
            {
                "retention_days": self.retention_days,
                "removed": removed,
                "tenant_id": tenant_id,
                "application_id": application_id,
            },
        )
        return {
            "applied": True,
            "removed": removed,
            "retention_days": self.retention_days,
            "tenant_id": tenant_id,
            "application_id": application_id,
        }

    def forensic_summary(
        self,
        limit: int = 5000,
        tenant_id: str | None = None,
        application_id: str | None = None,
    ) -> dict:
        return self.reporter.forensic_summary(limit=limit, tenant_id=tenant_id, application_id=application_id)

    def siem_events(
        self,
        limit: int = 1000,
        tenant_id: str | None = None,
        application_id: str | None = None,
    ) -> list[dict]:
        return self.reporter.siem_events(limit=limit, tenant_id=tenant_id, application_id=application_id)

    def siem_cef_events(
        self,
        limit: int = 1000,
        tenant_id: str | None = None,
        application_id: str | None = None,
    ) -> list[str]:
        return self.reporter.siem_cef_events(limit=limit, tenant_id=tenant_id, application_id=application_id)

    def incident_report(self, incident_id: str) -> dict:
        return self.reporter.incident_report(incident_id)

    def local_threat_feed(self, limit: int = 5000) -> dict:
        return self.threat_intel.local_feed(limit=limit)

    def export_threat_share_bundle(self, limit: int = 5000) -> dict:
        return self.threat_intel.export_share_bundle(limit=limit)

    def import_threat_share_bundle(self, payload: dict, *, source: str = "community") -> dict:
        out = self.threat_intel.import_share_bundle(payload, source=source)
        self.registry.record_audit("import_threat_share_bundle", out)
        return out

    def set_threat_sharing_opt_in(self, enabled: bool) -> None:
        self.registry.set_threat_sharing_opt_in(enabled)
        self.registry.record_audit("set_threat_sharing_opt_in", {"enabled": bool(enabled)})

    def threat_sharing_status(self) -> dict:
        return {"opt_in_enabled": self.registry.threat_sharing_opt_in()}

    def network_signatures(self, limit: int = 500, offset: int = 0) -> list[dict]:
        return self.threat_intel.network_signatures(limit=limit, offset=offset)

    def network_threat_matches(self, *, local_limit: int = 5000, network_limit: int = 5000) -> dict:
        return self.threat_intel.network_matches(local_limit=local_limit, network_limit=network_limit)

    def threat_transparency_report(self, *, local_limit: int = 5000, network_limit: int = 5000) -> dict:
        return self.threat_intel.transparency_report(local_limit=local_limit, network_limit=network_limit)

    def attack_pattern_library(self, *, local_limit: int = 5000) -> dict:
        return self.threat_intel.attack_pattern_library(local_limit=local_limit)

    def audit_log(self, limit: int = 100, offset: int = 0) -> list[dict]:
        return self.registry.list_audit(limit=limit, offset=offset)

    def create_api_key(
        self,
        *,
        name: str,
        key: str,
        role: str = "reader",
        tenant_id: str | None = None,
        application_id: str | None = None,
    ) -> dict:
        out = self.registry.create_api_key(
            name=name,
            key=key,
            role=role,
            tenant_id=tenant_id,
            application_id=application_id,
        )
        self.registry.record_audit(
            "create_api_key",
            {
                "id": out["id"],
                "name": name,
                "role": role,
                "tenant_id": tenant_id,
                "application_id": application_id,
            },
        )
        return out

    def list_api_keys(self, *, include_inactive: bool = True) -> list[dict]:
        return self.registry.list_api_keys(include_inactive=include_inactive)

    def revoke_api_key(self, key_id: int) -> bool:
        revoked = self.registry.revoke_api_key(key_id)
        self.registry.record_audit("revoke_api_key", {"id": key_id, "revoked": revoked})
        return revoked

    def rotate_api_key(self, *, key_id: int, new_key: str) -> dict:
        out = self.registry.rotate_api_key(key_id=key_id, new_key=new_key)
        if out is None:
            return {"old_key_revoked": False, "new_key": None}
        self.registry.record_audit(
            "rotate_api_key",
            {"old_key_id": key_id, "new_key_id": out["new_key"]["id"], "revoked": out["old_key_revoked"]},
        )
        return out

    def export_alerts_jsonl(
        self,
        path: str,
        *,
        limit: int = 1000,
        severity: str | None = None,
        detection_surface: str | None = None,
        conversation_id: str | None = None,
        incident_id: str | None = None,
        since: str | None = None,
        until: str | None = None,
        redact: bool = False,
        tenant_id: str | None = None,
        application_id: str | None = None,
    ) -> int:
        return self.exporter.export_jsonl(
            path,
            limit=limit,
            severity=severity,
            detection_surface=detection_surface,
            conversation_id=conversation_id,
            incident_id=incident_id,
            since=since,
            until=until,
            redact=redact,
            tenant_id=tenant_id,
            application_id=application_id,
        )

    def export_alerts_csv(
        self,
        path: str,
        *,
        limit: int = 1000,
        severity: str | None = None,
        detection_surface: str | None = None,
        conversation_id: str | None = None,
        incident_id: str | None = None,
        since: str | None = None,
        until: str | None = None,
        redact: bool = False,
        tenant_id: str | None = None,
        application_id: str | None = None,
    ) -> int:
        return self.exporter.export_csv(
            path,
            limit=limit,
            severity=severity,
            detection_surface=detection_surface,
            conversation_id=conversation_id,
            incident_id=incident_id,
            since=since,
            until=until,
            redact=redact,
            tenant_id=tenant_id,
            application_id=application_id,
        )

    def recent_incidents(self, limit: int = 50):
        return self.incidents.recent_incidents(limit=limit)

    def _should_dispatch(self, event: AlertEvent) -> bool:
        if self.rate_limiter is not None and not self.rate_limiter.should_dispatch(event):
            return False
        if self.min_dispatch_severity is None:
            return True
        return self._severity_rank(event.severity.value) >= self._severity_rank(self.min_dispatch_severity)

    def _dispatch_network_match_if_opted_in(self, event: AlertEvent) -> None:
        if not self.registry.threat_sharing_opt_in():
            return
        signature = self.threat_intel._sig(event)
        match = self.registry.get_network_signature(signature)
        if not match:
            return
        shadow = event.model_copy(deep=True)
        note = (
            f"network_signature_match={signature} "
            f"network_count={match['count']} source={match.get('source')}"
        )
        shadow.forensic_notes = f"{event.forensic_notes} | {note}".strip(" |")
        if self._should_dispatch(shadow):
            self.alerter.dispatch(shadow)
        self.registry.record_audit(
            "network_signature_match",
            {
                "alert_id": event.id,
                "signature": signature,
                "network_count": match["count"],
                "source": match.get("source"),
            },
        )

    @staticmethod
    def _severity_rank(severity: str) -> int:
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        return order[severity]

    def _context_from_llm_call(self, args, kwargs) -> dict:
        context: dict = {}
        metadata = kwargs.get("metadata")
        if isinstance(metadata, dict):
            context["session_metadata"] = metadata
        if "conversation_id" in kwargs:
            context["conversation_id"] = kwargs.get("conversation_id")
        if "messages" in kwargs and "conversation_id" not in context:
            messages = kwargs.get("messages")
            if isinstance(messages, list):
                for msg in messages:
                    if isinstance(msg, dict):
                        if "conversation_id" in msg:
                            context["conversation_id"] = msg["conversation_id"]
                            break
                        if "id" in msg:
                            context["conversation_id"] = str(msg["id"])
                            break
        if "session_metadata" not in context:
            context["session_metadata"] = {"args_count": len(args), "has_messages": "messages" in kwargs}
        return self._with_default_tenant(context)

    def _with_default_tenant(self, context: dict | None) -> dict:
        base = dict(context or {})
        sm = dict(base.get("session_metadata") or {})
        if self.default_tenant_id and not sm.get("tenant_id"):
            sm["tenant_id"] = self.default_tenant_id
        if self.default_application_id and not sm.get("application_id"):
            sm["application_id"] = self.default_application_id
        base["session_metadata"] = sm
        if self.default_tenant_id and not base.get("tenant_id"):
            base["tenant_id"] = self.default_tenant_id
        if self.default_application_id and not base.get("application_id"):
            base["application_id"] = self.default_application_id
        return base


def init(alert_webhook: str | None = None, db_path: str = "canari.db") -> CanariClient:
    client = CanariClient(db_path=db_path)
    if alert_webhook:
        client.alerter.add_webhook(alert_webhook)
    return client


__all__ = [
    "AlertEvent",
    "AlertDispatcher",
    "CanariClient",
    "CanaryGenerator",
    "CanaryRegistry",
    "CanaryToken",
    "IncidentManager",
    "InjectionStrategy",
    "OutputScanner",
    "TokenType",
    "EgressMonitor",
    "DashboardServer",
    "ForensicReporter",
    "AlertExporter",
    "AlertRateLimiter",
    "ThreatIntelBuilder",
    "wrap_runnable",
    "wrap_chain",
    "wrap_query_engine",
    "patch_openai_client",
    "init",
]
