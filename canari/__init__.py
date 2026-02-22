import asyncio

from canari.alerter import AlertDispatcher
from canari.generator import CanaryGenerator
from canari.integrations import inject_canaries_into_index, wrap_chain, wrap_query_engine
from canari.injector import inject_as_document, inject_into_system_prompt, wrap_context_assembler
from canari.models import AlertEvent, CanaryToken, InjectionStrategy, TokenType
from canari.registry import CanaryRegistry
from canari.scanner import OutputScanner


class CanariClient:
    def __init__(self, db_path: str = "canari.db"):
        self.registry = CanaryRegistry(db_path=db_path)
        self.generator = CanaryGenerator()
        self.scanner = OutputScanner(self.registry)
        self.alerter = AlertDispatcher()
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
                self.scan_output(output)
                return result

            return async_wrapped

        def wrapped(*args, **kwargs):
            result = llm_fn(*args, **kwargs)
            output = self.scanner._extract_text(result)
            self.scan_output(output)
            return result

        return wrapped

    def wrap_chain(self, chain):
        return wrap_chain(chain, self.scan_output)

    def wrap_query_engine(self, query_engine):
        return wrap_query_engine(query_engine, self.scan_output)

    def scan_output(self, output: str, context: dict | None = None) -> list[AlertEvent]:
        events = self.scanner.scan(output, context=context)
        for event in events:
            self.alerter.dispatch(event)
        return events


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
    "InjectionStrategy",
    "OutputScanner",
    "TokenType",
    "wrap_chain",
    "wrap_query_engine",
    "init",
]
