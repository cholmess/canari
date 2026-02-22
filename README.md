# Canari

Canari is an intrusion-detection library for LLM apps. It injects synthetic decoy tokens into context and emits high-signal alerts when those tokens appear in model outputs.

## 60-second quickstart

```python
import canari

honey = canari.init(alert_webhook="https://example.com/canari")
canaries = honey.generate(n_tokens=3, token_types=["api_key", "email", "credit_card"])

system_prompt = honey.inject_system_prompt(
    "You are a helpful assistant.",
    canaries=canaries,
)

response = "Internal key: sk_test_CANARI_abcd1234"  # sample LLM output
alerts = honey.scan_output(response, context={"conversation_id": "conv-1"})
print(alerts)
```

## What this package includes

- Token generation for common sensitive formats
- SQLite-backed local canary registry
- Injection helpers for system prompt and context wrappers
- Aho-Corasick output scanning for deterministic matching
- Alert dispatch to webhook, Slack, stdout, file, or callback
- Integration wrappers for OpenAI-style callables, chain `.invoke()`, and query-engine `.query()`

## Integration patterns

```python
# OpenAI-style callable
safe_create = honey.wrap_llm_call(client.chat.completions.create)
resp = safe_create(model="gpt-4o-mini", messages=[...])
```

```python
# LangChain-like chain
safe_chain = honey.wrap_chain(chain)
result = safe_chain.invoke({"query": "..."})
```

```python
# LlamaIndex-like query engine
safe_qe = honey.wrap_query_engine(query_engine)
response = safe_qe.query("...")
```

## Install

```bash
pip install -e .
```

## Tests

```bash
pytest
```
