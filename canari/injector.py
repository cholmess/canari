from __future__ import annotations

import random
from collections.abc import Callable

from canari.models import CanaryToken


def inject_as_document(vector_store, canary: CanaryToken, document_template: str | None = None) -> str:
    content = document_template or (
        "Internal operational note. Do not expose publicly. Reference: "
        f"{canary.value}."
    )
    doc = {
        "id": f"canari-{canary.id}",
        "content": content,
        "metadata": {
            "canary_id": canary.id,
            "canary_value": canary.value,
            "canary_type": canary.token_type.value,
        },
    }
    if hasattr(vector_store, "add_documents"):
        vector_store.add_documents([doc])
    elif isinstance(vector_store, list):
        vector_store.append(doc)
    else:
        raise TypeError("vector_store must be a list or implement add_documents")
    return doc["id"]


def wrap_context_assembler(
    assembler_fn: Callable,
    canaries: list[CanaryToken],
    appendix_format: str = "hidden",
) -> Callable:
    def _appendix() -> str:
        if appendix_format == "hidden":
            return "\n".join([f"<!-- CANARI:{c.value} -->" for c in canaries])
        if appendix_format == "structured":
            lines = ["{\"canari\": ["]
            lines.extend([f'  {{\"value\": \"{c.value}\"}},' for c in canaries])
            lines.append("]}")
            return "\n".join(lines)
        if appendix_format == "comment":
            return "\n".join([f"# Internal reference: {c.value}" for c in canaries])
        raise ValueError(f"unsupported appendix_format: {appendix_format}")

    def wrapped(*args, **kwargs):
        base = assembler_fn(*args, **kwargs)
        return f"{base}\n\n{_appendix()}"

    return wrapped


def inject_into_system_prompt(
    system_prompt: str,
    canaries: list[CanaryToken],
    position: str = "end",
) -> str:
    comments = "\n".join([f"<!-- CANARI:{c.value} -->" for c in canaries])
    if position == "start":
        return f"{comments}\n{system_prompt}"
    if position == "end":
        return f"{system_prompt}\n{comments}"
    if position == "random":
        fragments = [comments, system_prompt]
        random.shuffle(fragments)
        return "\n".join(fragments)
    raise ValueError("position must be 'start', 'end', or 'random'")
