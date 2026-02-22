# Integration Guide

Canari integrates at the call boundary where model outputs become available.

## OpenAI-style callable

```python
safe_create = honey.wrap_llm_call(client.chat.completions.create)
resp = safe_create(model="gpt-4o-mini", messages=[...])
```

## OpenAI client patch

```python
honey.patch_openai_client(client)
resp = client.chat.completions.create(model="gpt-4o-mini", messages=[...])
```

## LangChain-style chain

```python
safe_chain = honey.wrap_chain(chain)
out = safe_chain.invoke({"query": "..."})
```

## Runnable-style API

```python
safe_runnable = honey.wrap_runnable(runnable)
out = safe_runnable.invoke({"query": "..."})
```

## LlamaIndex-style query engine

```python
safe_qe = honey.wrap_query_engine(query_engine)
out = safe_qe.query("...")
```

## HTTP egress monitoring

```python
honey.monitor_http_request(
    "POST",
    "https://api.example.com/submit",
    headers={"Authorization": "Bearer ..."},
    body={"payload": "..."},
)
```

## Injection patterns

- `inject_system_prompt(...)` for direct prompt instrumentation.
- `wrap_context_assembler(...)` for centralized context builders.
- `inject_vectorstore(...)` and `inject_index(...)` for document-style placement.
