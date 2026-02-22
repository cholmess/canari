# Canari

Your LLM was just attacked. Canari knew before you did.

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
- Integration wrappers for OpenAI-style callables, Runnable `.invoke()/batch()`, chain `.invoke()`, and query-engine `.query()`
- Outbound HTTP egress monitoring for canary token exfiltration attempts
- Deterministic exfiltration-pattern assessment (`low`/`medium`/`high`/`critical`)
- Registry exposure stats (`total/active/by_type/by_strategy`)
- Conversation-level correlation (`incident_id`, `correlation_count`) for repeated/multi-surface attacks
- Local alert journal in SQLite (`alert_history`, `alert_stats`)
- Forensic reporting (`forensic_summary`, `incident_report`)
- Export helpers (`export_alerts_jsonl`, `export_alerts_csv`)
- Built-in CLI (`canari` or `python -m canari`)
- Alert journal retention (`purge_alerts_older_than`)
- Optional alert dispatch rate limiting (`set_alert_rate_limit`)
- Local dashboard server (`serve-dashboard`)
- Local threat-intel feed (`threat-feed`)
- Webhook integrity signing (`signing_secret` -> `X-Canari-Signature`)
- Default tenant context (`set_default_tenant`) for multi-tenant apps
- Administrative audit log (`audit-log`)

## Integration patterns

```python
# OpenAI-style callable
safe_create = honey.wrap_llm_call(client.chat.completions.create)
resp = safe_create(model="gpt-4o-mini", messages=[...])
```

```python
# OpenAI SDK client patching
honey.patch_openai_client(client)
resp = client.chat.completions.create(model="gpt-4o-mini", messages=[...])
```

```python
# Runnable-style object (LangChain core)
safe_runnable = honey.wrap_runnable(runnable)
result = safe_runnable.invoke({"query": "..."})
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

```python
# Outbound HTTP request monitoring
honey.monitor_http_request(
    "POST",
    "https://api.example.com/submit",
    headers={"Authorization": "Bearer ..."},
    body={"payload": "..."},
)
```

## Webhook payload shape

Webhook/file JSON alerts follow this structure:

```json
{
  "canari_version": "0.1.0",
  "alert_id": "uuid",
  "severity": "high",
  "triggered_at": "2026-02-22T14:30:00Z",
  "canary": {
    "id": "canary-uuid",
    "type": "stripe_key",
    "value": "sk_test_CANARI_abc123",
    "injected_at": "2026-02-22T09:00:00Z",
    "injection_strategy": "document_metadata",
    "injection_location": "RAG vector store document"
  },
  "trigger": {
    "detection_surface": "output",
    "output_snippet": "...",
    "conversation_id": "conv-uuid",
    "incident_id": "inc-conv-uuid-12345",
    "correlation_count": 1,
    "session_metadata": {}
  },
  "forensic_notes": "Token appeared in full in LLM output."
}
```

## Install

```bash
pip install -e .
```

Optional extras:

```bash
pip install -e .[openai]
pip install -e .[langchain]
pip install -e .[llamaindex]
pip install -e .[speed]
```

## Tests

```bash
pytest
```

Registry stats:

```python
stats = honey.registry_stats()
print(stats["total_tokens"], stats["active_tokens"])
```

Recent incidents:

```python
incidents = honey.recent_incidents(limit=20)
for i in incidents:
    print(i.incident_id, i.max_severity, i.event_count)
```

Alert journal:

```python
alerts = honey.alert_history(limit=25, severity="critical")
stats = honey.alert_stats()
print(len(alerts), stats["total_alerts"])
print(stats["by_token_type"], stats["top_conversations"])
print(stats["by_tenant"])
```

Rate limit dispatch noise:

```python
honey.set_alert_rate_limit(window_seconds=60, max_dispatches=3)
# ...
honey.disable_alert_rate_limit()
```

Default tenant context:

```python
honey.set_default_tenant("acme-prod")
# alerts generated without explicit tenant_id inherit this tenant
honey.clear_default_tenant()
```

Forensic reports:

```python
summary = honey.forensic_summary(limit=1000)
incident = honey.incident_report("inc-conv-123-456")
print(summary["alerts"]["total_alerts"], incident["found"])
```

Export alerts:

```python
honey.export_alerts_jsonl("/tmp/canari-alerts.jsonl", severity="critical")
honey.export_alerts_csv("/tmp/canari-alerts.csv", detection_surface="network_egress")
```

Signed webhooks:

```python
honey.alerter.add_webhook(
    "https://example.com/canari",
    signing_secret="replace-with-strong-secret",
)
```

Receiver-side verification:

```python
is_valid = canari.AlertDispatcher.verify_signature(payload, headers, "replace-with-strong-secret")
```

CLI usage:

```bash
canari --db canari.db token-stats
canari --db canari.db --compact token-stats
canari --db canari.db alert-stats
canari --db canari.db alerter-health
canari --db canari.db audit-log --limit 50
canari --db canari.db doctor
canari --db canari.db policy show
canari --db canari.db policy set --min-severity high --rate-window 120 --rate-max 4
canari --db canari.db seed --n 5 --types api_key,email,stripe_key
canari --db canari.db rotate-canaries --n 5 --types api_key,email
canari --db canari.db alerts --limit 20 --severity critical
canari --db canari.db alerts --incident inc-conv-123-456
canari --db canari.db alerts --tenant acme-prod --limit 50
canari --db canari.db alerts --since 2026-02-01T00:00:00+00:00 --until 2026-02-28T23:59:59+00:00
canari --db canari.db incidents --limit 20
canari --db canari.db forensic-summary --limit 5000
canari --db canari.db threat-feed --limit 5000
canari --db canari.db incident-replay --incident inc-conv-123-456 --out /tmp/incident.jsonl
canari --db canari.db scan-text --text "leak sk_test_CANARI_x" --conversation conv-1
canari --db canari.db export --format jsonl --out /tmp/canari-alerts.jsonl
canari --db canari.db export --format csv --out /tmp/canari-alerts.csv --since 2026-02-01T00:00:00+00:00
canari --db canari.db export --format jsonl --out /tmp/canari-redacted.jsonl --redact
canari --db canari.db purge-alerts --older-than-days 30
canari --db canari.db backup-db --out /tmp/canari-backup.db
canari --db canari.db serve-dashboard --host 127.0.0.1 --port 8080
canari --db canari.db serve-dashboard --host 127.0.0.1 --port 8080 --api-token secret123
```

## CI and release checks

- CI test workflow: `.github/workflows/ci.yml`
- Build + twine validation workflow: `.github/workflows/release-check.yml`
