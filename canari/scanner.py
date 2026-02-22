from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable
from datetime import datetime, timezone

try:
    import ahocorasick
except ModuleNotFoundError:  # pragma: no cover
    ahocorasick = None

from canari.detection import ExfiltrationAnalyzer
from canari.models import AlertEvent, AlertSeverity, CanaryToken, TokenType
from canari.registry import CanaryRegistry


class OutputScanner:
    def __init__(self, registry: CanaryRegistry):
        self.registry = registry
        self._token_index: dict[str, CanaryToken] = {}
        self._automaton = None
        self._registry_signature = ""
        self.analyzer = ExfiltrationAnalyzer()
        self._rebuild_index()

    def _rebuild_index(self) -> None:
        self._token_index.clear()
        self._automaton = None
        if ahocorasick is not None:
            self._automaton = ahocorasick.Automaton()
        active_tokens = self.registry.list_active()
        for token in active_tokens:
            self._token_index[token.value] = token
            if self._automaton is not None:
                self._automaton.add_word(token.value, token.value)
        if self._automaton is not None:
            self._automaton.make_automaton()
        self._registry_signature = self._signature(active_tokens)

    @staticmethod
    def _signature(tokens: list[CanaryToken]) -> str:
        # Stable signature for drift detection of active token set.
        return "|".join(sorted(f"{t.id}:{t.active}:{t.value}" for t in tokens))

    def _severity_for(self, token: CanaryToken, hit_count: int) -> AlertSeverity:
        assessment = self.analyzer.assess(token, "", hit_count)
        return assessment.severity

    def scan(self, output: str, context: dict | None = None) -> list[AlertEvent]:
        context = context or {}
        active_tokens = self.registry.list_active()
        sig = self._signature(active_tokens)
        if sig != self._registry_signature:
            self._rebuild_index()

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
        scan_time = datetime.now(timezone.utc)
        for token in hits:
            idx = output.find(token.value)
            snippet_start = max(0, idx - 60)
            snippet_end = min(len(output), idx + len(token.value) + 60)
            snippet = output[snippet_start:snippet_end]
            assessment = self.analyzer.assess(token, output, len(hits))
            delta = scan_time - token.injection_timestamp.astimezone(timezone.utc)
            interval = str(delta).split(".", maxsplit=1)[0]
            events.append(
                AlertEvent(
                    id=str(uuid.uuid4()),
                    canary_id=token.id,
                    canary_value=token.value,
                    token_type=token.token_type,
                    injection_strategy=token.injection_strategy,
                    injection_location=token.injection_location,
                    injected_at=token.injection_timestamp,
                    severity=assessment.severity,
                    triggered_at=scan_time,
                    conversation_id=context.get("conversation_id"),
                    output_snippet=snippet,
                    full_output=output,
                    session_metadata=context.get("session_metadata", {}),
                    forensic_notes=(
                        "Token appeared in LLM output. Deterministic canary match "
                        f"for strategy={token.injection_strategy.value}. "
                        f"Assessment={assessment.reason}. Injection-to-trigger interval={interval}."
                    ),
                    detection_surface="output",
                    tenant_id=(context.get("session_metadata", {}) or {}).get("tenant_id"),
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
        if hasattr(result, "choices"):
            choices = getattr(result, "choices", []) or []
            if choices:
                choice = choices[0]
                message = getattr(choice, "message", None)
                if message is not None and hasattr(message, "content"):
                    content = getattr(message, "content")
                    if isinstance(content, str):
                        return content
                    if isinstance(content, list):
                        text_parts = []
                        for item in content:
                            if isinstance(item, str):
                                text_parts.append(item)
                            elif isinstance(item, dict):
                                text_parts.append(str(item.get("text", "")))
                            else:
                                text_parts.append(str(getattr(item, "text", "")))
                        return "".join(text_parts)
        if hasattr(result, "content"):
            return str(result.content)
        if isinstance(result, dict):
            for key in ("output", "output_text", "text", "content", "answer", "result"):
                if key in result:
                    return str(result[key])
            if "choices" in result and result["choices"]:
                choice = result["choices"][0]
                if isinstance(choice, dict):
                    msg = choice.get("message", {})
                    if isinstance(msg, dict) and "content" in msg:
                        return str(msg["content"])
        return str(result)
