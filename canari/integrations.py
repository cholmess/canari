from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from canari.injector import inject_as_document


@dataclass
class ChainWrapper:
    chain: Any
    scan_and_dispatch: Callable[[str, dict | None], list]

    def invoke(self, payload, **kwargs):
        result = self.chain.invoke(payload, **kwargs)
        self.scan_and_dispatch(_extract_text(result), context={"payload": payload})
        return result

    def run(self, *args, **kwargs):
        result = self.chain.run(*args, **kwargs)
        self.scan_and_dispatch(_extract_text(result), context={"args": args})
        return result


@dataclass
class QueryEngineWrapper:
    query_engine: Any
    scan_and_dispatch: Callable[[str, dict | None], list]

    def query(self, query_text: str, **kwargs):
        result = self.query_engine.query(query_text, **kwargs)
        self.scan_and_dispatch(_extract_text(result), context={"query": query_text})
        return result


def wrap_chain(chain: Any, scan_and_dispatch: Callable[[str, dict | None], list]) -> ChainWrapper:
    if not hasattr(chain, "invoke") and not hasattr(chain, "run"):
        raise TypeError("chain must expose invoke() or run()")
    return ChainWrapper(chain=chain, scan_and_dispatch=scan_and_dispatch)


def wrap_query_engine(
    query_engine: Any,
    scan_and_dispatch: Callable[[str, dict | None], list],
) -> QueryEngineWrapper:
    if not hasattr(query_engine, "query"):
        raise TypeError("query_engine must expose query()")
    return QueryEngineWrapper(query_engine=query_engine, scan_and_dispatch=scan_and_dispatch)


def inject_index(index: Any, docs: list[dict]) -> list[str]:
    inserted_ids: list[str] = []
    if isinstance(index, list):
        index.extend(docs)
        return [d.get("id", "") for d in docs]

    if hasattr(index, "insert"):
        for doc in docs:
            result = index.insert(doc)
            inserted_ids.append(str(result) if result else doc.get("id", ""))
        return inserted_ids

    if hasattr(index, "add_documents"):
        index.add_documents(docs)
        return [d.get("id", "") for d in docs]

    raise TypeError("index must be a list or expose insert()/add_documents()")


def inject_canaries_into_index(index: Any, canaries: list) -> list[str]:
    docs = []
    for canary in canaries:
        doc = {
            "id": f"canari-{canary.id}",
            "content": f"Reference material: {canary.value}",
            "metadata": {
                "canary_id": canary.id,
                "canary_value": canary.value,
                "canary_type": canary.token_type.value,
            },
        }
        docs.append(doc)

    if isinstance(index, list) or hasattr(index, "insert") or hasattr(index, "add_documents"):
        return inject_index(index, docs)

    # Backward-compatible path through the generic document injector.
    inserted_ids = []
    for canary in canaries:
        inserted_ids.append(inject_as_document(index, canary))
    return inserted_ids


def _extract_text(result: Any) -> str:
    if isinstance(result, str):
        return result
    if hasattr(result, "response"):
        return str(result.response)
    if hasattr(result, "content"):
        return str(result.content)
    if isinstance(result, dict):
        for key in ("result", "output", "text", "content", "answer"):
            if key in result:
                return str(result[key])
    return str(result)
