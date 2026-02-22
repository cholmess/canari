from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable
from datetime import datetime, timezone

try:
    import ahocorasick
except ModuleNotFoundError:  # pragma: no cover
    ahocorasick = None

from canari.models import AlertEvent, AlertSeverity, CanaryToken, TokenType
from canari.registry import CanaryRegistry


class OutputScanner:
    def __init__(self, registry: CanaryRegistry):
        self.registry = registry
        self._token_index: dict[str, CanaryToken] = {}
        self._automaton = None
        self._rebuild_index()

    def _rebuild_index(self) -> None:
        self._token_index.clear()
        if ahocorasick is not None:
            self._automaton = ahocorasick.Automaton()
        for token in self.registry.list_active():
            self._token_index[token.value] = token
            if self._automaton is not None:
                self._automaton.add_word(token.value, token.value)
        if self._automaton is not None:
            self._automaton.make_automaton()

    def _severity_for(self, token: CanaryToken, hit_count: int) -> AlertSeverity:
        if token.token_type in {TokenType.AWS_KEY, TokenType.STRIPE_KEY, TokenType.GITHUB_TOKEN}:
            return AlertSeverity.HIGH
        if hit_count > 1:
            return AlertSeverity.MEDIUM
        return AlertSeverity.LOW

    def scan(self, output: str, context: dict | None = None) -> list[AlertEvent]:
        context = context or {}
        hits: list[CanaryToken] = []
        seen = set()
        if self._automaton is not None:
            for _, matched_value in self._automaton.iter(output):
                if matched_value not in seen:
                    token = self._token_index.get(matched_value)
                    if token:
                        hits.append(token)
                        seen.add(matched_value)
        else:
            for value, token in self._token_index.items():
                if value in output and value not in seen:
                    hits.append(token)
                    seen.add(value)

        events: list[AlertEvent] = []
        for token in hits:
            idx = output.find(token.value)
            snippet_start = max(0, idx - 60)
            snippet_end = min(len(output), idx + len(token.value) + 60)
            snippet = output[snippet_start:snippet_end]
            events.append(
                AlertEvent(
                    id=str(uuid.uuid4()),
                    canary_id=token.id,
                    canary_value=token.value,
                    token_type=token.token_type,
                    severity=self._severity_for(token, len(hits)),
                    triggered_at=datetime.now(timezone.utc),
                    conversation_id=context.get("conversation_id"),
                    output_snippet=snippet,
                    full_output=output,
                    session_metadata=context.get("session_metadata", {}),
                    forensic_notes=(
                        "Token appeared in LLM output. Deterministic canary match "
                        f"for strategy={token.injection_strategy.value}."
                    ),
                )
            )
        return events

    async def scan_async(self, output: str, context: dict | None = None) -> list[AlertEvent]:
        await asyncio.sleep(0)
        return self.scan(output, context=context)

    def wrap_llm_call(self, llm_fn: Callable) -> Callable:
        if asyncio.iscoroutinefunction(llm_fn):

            async def async_wrapped(*args, **kwargs):
                result = await llm_fn(*args, **kwargs)
                content = self._extract_text(result)
                self.scan(content)
                return result

            return async_wrapped

        def wrapped(*args, **kwargs):
            result = llm_fn(*args, **kwargs)
            content = self._extract_text(result)
            self.scan(content)
            return result

        return wrapped

    @staticmethod
    def _extract_text(result) -> str:
        if isinstance(result, str):
            return result
        if hasattr(result, "content"):
            return str(result.content)
        if isinstance(result, dict):
            for key in ("output", "text", "content"):
                if key in result:
                    return str(result[key])
        return str(result)
