# Canari

[![PyPI version](https://badge.fury.io/py/canari-llm.svg)](https://pypi.org/project/canari-llm/)
[![CI](https://github.com/cholmess/canari/actions/workflows/ci.yml/badge.svg)](https://github.com/cholmess/canari/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Honeypot tokens for LLM and RAG applications.

Prompt injection is the #1 vulnerability in LLM applications (OWASP LLM Top 10).
An attacker can exfiltrate your entire RAG context through a chat interface and
your firewall will never flag a single packet, because the exfiltration looks
exactly like a legitimate API response. You find out weeks later, if ever.

Canari injects synthetic decoy tokens into your LLM context. When an attacker
successfully extracts them, you know immediately with zero false positives,
because the token exists nowhere legitimate.

Canary tokens have protected traditional infrastructure for years. Canari brings
the same principle to LLM applications: put something fake in the place attackers
target, instrument it, and alert on contact. If it fires, it's a breach.

## Demo

![Canari attack demo](https://raw.githubusercontent.com/cholmess/canari/main/docs/assets/attack-demo.gif)

Expected output center-frame:

```text
CANARI ALERT - CANARY FIRED
Severity: HIGH
Token type: stripe_key
This is a confirmed prompt injection attack.
```

## Install

```bash
pip install canari-llm
```

## 60-second quickstart

```python
import canari

honey = canari.init(alert_webhook="https://example.com/canari")
canaries = honey.generate(n_tokens=3, token_types=["api_key", "email", "credit_card"])

system_prompt = honey.inject_system_prompt(
    "You are a helpful assistant.",
    canaries=canaries,
)

response = "Internal key: sk_test_CANARI_abcd1234"
alerts = honey.scan_output(response, context={"conversation_id": "conv-1"})
print(len(alerts))
```

## Run the attack demo

```bash
cd examples/attack_demo
pip install -r requirements.txt
python app.py --offline
```

## How it works

Canari generates deterministic fake secrets that look real enough to be attractive targets for prompt injection attacks. You insert those decoys into system prompts, hidden context appendices, or document-style RAG content while keeping a local registry of what was planted and where.

When a model response is produced, Canari scans output with exact token matching and deterministic fallback paths. Any hit is definitive because each canary was synthetically created by your deployment and does not belong in legitimate output.

Every hit becomes a structured alert event with severity, context, and timeline attributes. You can dispatch immediately to stdout, webhooks, and Slack, then query incidents and forensic summaries from local SQLite without shipping your data to an external service.

## Integration patterns

```python
safe_create = honey.wrap_llm_call(client.chat.completions.create)
resp = safe_create(model="gpt-4o-mini", messages=[...])
```

```python
honey.patch_openai_client(client)
resp = client.chat.completions.create(model="gpt-4o-mini", messages=[...])
```

```python
safe_chain = honey.wrap_chain(chain)
safe_runnable = honey.wrap_runnable(runnable)
safe_qe = honey.wrap_query_engine(query_engine)
```

## Alert channels

- Webhook: signed payloads with `X-Canari-Signature` support.
- Slack: push concise incident notifications.
- Stdout/file/callback: local ops-friendly alert sinks.

More details: `docs/alert-channels.md`.

## CLI (Top 10)

```bash
canari --db canari.db seed --n 5 --types api_key,email,credit_card
canari --db canari.db token-stats
canari --db canari.db alerts --limit 20
canari --db canari.db alerts --severity critical
canari --db canari.db incidents --limit 20
canari --db canari.db incident-report inc-conv-123-456
canari --db canari.db scan-text --text "leak sk_test_CANARI_x"
canari --db canari.db forensic-summary
canari --db canari.db rotate-canaries --n 5
canari --db canari.db serve-dashboard --host 127.0.0.1 --port 8080
```

## Advanced features

- Full CLI: `docs/cli-reference.md`
- Enterprise controls: `docs/enterprise.md`
- Threat intel: `docs/threat-intelligence.md`
- Integration deep dive: `docs/integration-guide.md`
- Token generation details: `docs/token-types.md`
- Show HN launch draft: `docs/show-hn.md`

## Maintainer

Maintained by Christopher Holmes Silva.

- X: https://x.com/cholmess
- LinkedIn: https://linkedin.com/in/christopher-holmes-silva

Feedback is welcome from developers building LLM apps.
