import asyncio

from canari.adapters import patch_openai_client, wrap_runnable
from canari.alerter import AlertDispatcher
from canari.generator import CanaryGenerator
from canari.incidents import IncidentManager
from canari.integrations import inject_canaries_into_index, wrap_chain, wrap_query_engine
from canari.injector import inject_as_document, inject_into_system_prompt, wrap_context_assembler
from canari.monitor import EgressMonitor
from canari.models import AlertEvent, CanaryToken, InjectionStrategy, TokenType
from canari.rate_limit import AlertRateLimiter
from canari.exporter import AlertExporter
from canari.reporting import ForensicReporter
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
        self.rate_limiter: AlertRateLimiter | None = None
        self.alerter = AlertDispatcher(canari_version=__version__)
        self.alerter.add_stdout()

    def generate(self, n_tokens: int = 1, token_types: list[str] | None = None) -> list[CanaryToken]:
        kinds = token_types or [TokenType.API_KEY.value]
        selected = [TokenType(k) for k in kinds]
        tokens = []
        for i in range(n_tokens):
            token_type = selected[i % len(selected)]
            token = self.generator.generate(token_type)
            self.registry.add(token)
            tokens.append(token)
        self.scanner._rebuild_index()
        return tokens

    def rotate_canaries(self, n_tokens: int = 3, token_types: list[str] | None = None) -> dict:
        active = self.registry.list_active()
        deactivated = 0
        for token in active:
            if self.registry.deactivate(token.id):
                deactivated += 1
        self.scanner._rebuild_index()
        generated = self.generate(n_tokens=n_tokens, token_types=token_types)
        return {
            "deactivated": deactivated,
            "generated": len(generated),
            "active_now": len(self.registry.list_active()),
        }

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
        events = self.scanner.scan(output, context=context)
        correlated_events = []
        for event in events:
            correlated = self.incidents.correlate(event)
            correlated_events.append(correlated)
            self.registry.record_alert(correlated)
            if self.rate_limiter is None or self.rate_limiter.should_dispatch(correlated):
                self.alerter.dispatch(correlated)
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
            if self.rate_limiter is None or self.rate_limiter.should_dispatch(correlated):
                self.alerter.dispatch(correlated)
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
        severity: str | None = None,
        detection_surface: str | None = None,
        conversation_id: str | None = None,
        incident_id: str | None = None,
        since: str | None = None,
        until: str | None = None,
    ):
        return self.registry.list_alerts(
            limit=limit,
            severity=severity,
            detection_surface=detection_surface,
            conversation_id=conversation_id,
            incident_id=incident_id,
            since=since,
            until=until,
        )

    def alert_stats(self) -> dict:
        return self.registry.alert_stats()

    def purge_alerts_older_than(self, *, days: int) -> int:
        return self.registry.purge_alerts_older_than(days=days)

    def backup_db(self, path: str) -> int:
        return self.registry.backup_to(path)

    def doctor(self) -> dict:
        return self.registry.doctor()

    def alerter_health(self) -> dict:
        return self.alerter.health()

    def set_alert_rate_limit(self, *, window_seconds: int = 60, max_dispatches: int = 3) -> None:
        self.rate_limiter = AlertRateLimiter(window_seconds=window_seconds, max_dispatches=max_dispatches)

    def disable_alert_rate_limit(self) -> None:
        self.rate_limiter = None

    def forensic_summary(self, limit: int = 5000) -> dict:
        return self.reporter.forensic_summary(limit=limit)

    def incident_report(self, incident_id: str) -> dict:
        return self.reporter.incident_report(incident_id)

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
        )

    def recent_incidents(self, limit: int = 50):
        return self.incidents.recent_incidents(limit=limit)

    @staticmethod
    def _context_from_llm_call(args, kwargs) -> dict:
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
        return context


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
    "ForensicReporter",
    "AlertExporter",
    "AlertRateLimiter",
    "wrap_runnable",
    "wrap_chain",
    "wrap_query_engine",
    "patch_openai_client",
    "init",
]
