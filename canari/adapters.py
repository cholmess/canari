from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass
class RunnableWrapper:
    runnable: Any
    scan_and_dispatch: Callable[[str, dict | None], list]

    def invoke(self, input, *args, **kwargs):  # noqa: A002
        result = self.runnable.invoke(input, *args, **kwargs)
        self.scan_and_dispatch(_extract_text(result), context={"input": input})
        return result

    async def ainvoke(self, input, *args, **kwargs):  # noqa: A002
        if not hasattr(self.runnable, "ainvoke"):
            raise AttributeError("wrapped runnable has no ainvoke()")
        result = await self.runnable.ainvoke(input, *args, **kwargs)
        self.scan_and_dispatch(_extract_text(result), context={"input": input})
        return result

    def batch(self, inputs, *args, **kwargs):
        if not hasattr(self.runnable, "batch"):
            raise AttributeError("wrapped runnable has no batch()")
        results = self.runnable.batch(inputs, *args, **kwargs)
        for idx, result in enumerate(results):
            self.scan_and_dispatch(_extract_text(result), context={"batch_index": idx})
        return results

    async def abatch(self, inputs, *args, **kwargs):
        if not hasattr(self.runnable, "abatch"):
            raise AttributeError("wrapped runnable has no abatch()")
        results = await self.runnable.abatch(inputs, *args, **kwargs)
        for idx, result in enumerate(results):
            self.scan_and_dispatch(_extract_text(result), context={"batch_index": idx})
        return results

    def __getattr__(self, name: str):
        return getattr(self.runnable, name)


def wrap_runnable(runnable: Any, scan_and_dispatch: Callable[[str, dict | None], list]) -> RunnableWrapper:
    if not hasattr(runnable, "invoke") and not hasattr(runnable, "ainvoke"):
        raise TypeError("runnable must expose invoke() or ainvoke()")
    return RunnableWrapper(runnable=runnable, scan_and_dispatch=scan_and_dispatch)


def patch_openai_client(client: Any, wrap_llm_call: Callable[[Callable], Callable]) -> dict[str, int]:
    patched = 0

    def _patch(path: tuple[str, ...]) -> None:
        nonlocal patched
        target = client
        for attr in path[:-1]:
            if not hasattr(target, attr):
                return
            target = getattr(target, attr)
        leaf = path[-1]
        if not hasattr(target, leaf):
            return
        original = getattr(target, leaf)
        if not callable(original):
            return
        setattr(target, leaf, wrap_llm_call(original))
        patched += 1

    _patch(("chat", "completions", "create"))
    _patch(("responses", "create"))

    if patched == 0:
        raise TypeError("client does not look like an OpenAI SDK client")

    return {"patched_endpoints": patched}


def _extract_text(result: Any) -> str:
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        for key in ("result", "output", "output_text", "text", "content", "answer"):
            if key in result:
                return str(result[key])
        if "choices" in result and result["choices"]:
            choice = result["choices"][0]
            if isinstance(choice, dict):
                msg = choice.get("message", {})
                if isinstance(msg, dict) and "content" in msg:
                    return str(msg["content"])
    if hasattr(result, "content"):
        return str(result.content)
    return str(result)
