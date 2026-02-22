# Canari

Local LLM leak detection using canary tokens.

[![PyPI version](https://badge.fury.io/py/canari-llm.svg)](https://pypi.org/project/canari-llm/)
[![CI](https://github.com/cholmess/canari/actions/workflows/ci.yml/badge.svg)](https://github.com/cholmess/canari/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

LLM applications sometimes return internal values by mistake. Traditional monitoring rarely catches this because the response is technically valid application output. Canari injects decoy canary tokens into prompts or context and alerts when those tokens appear in model output.

## What Problem Does This Solve?

You keep sensitive values in prompts, RAG context, or internal documents. You need a deterministic way to know when those values leak into output. Canary tokens are tripwires: if one appears in output, the model leaked internal context.

Examples:

- API key leak: a support assistant returns `sk_test_...` from internal config text.
- RAG identifier leak: retrieval returns an internal document ID that should never leave the system boundary.
- Prompt injection leak: attacker asks for hidden context and the model prints seeded internal tokens.

## Demo

![Canari attack demo](https://raw.githubusercontent.com/cholmess/canari/main/docs/assets/attack-demo.gif)

## Install

```bash
pip install canari-llm
```

## Minimal 3-Step Quickstart

### Step 1: Generate a canary token

### Step 2: Inject it into prompt/context

### Step 3: Scan output and trigger alert

```python
import canari

honey = canari.init(db_path="canari.db")
honey.alerter._channels = []

# Step 1
canary = honey.generate(n_tokens=1, token_types=["api_key"])[0]

# Step 2 (simulate context containing the canary)
context = f"Internal config: billing_key={canary.value}"

# Step 3 (simulate model output leak)
model_output = f"Here is the value you asked for: {canary.value}"
alerts = honey.scan_output(model_output, context={"conversation_id": "quickstart-1"})

print(f"alerts: {len(alerts)}")
if alerts:
    print(f"ALERT: leak detected for {alerts[0].token_type.value} -> {alerts[0].canary_value}")
```

## Example Flow

1. Generate canary: `canari_abc123` (example marker)
2. Model output accidentally contains it.
3. Canari detects the exact token match.
4. Alert is triggered immediately.

Expected console output:

```text
alerts: 1
ALERT: leak detected for api_key -> api_canari_xxxxxxxx
```

## CLI-Based Local Flow

```bash
canari --db canari.db seed --n 3 --types api_key,email,credit_card
canari --db canari.db scan-text --text "leak api_canari_abcd1234"
canari --db canari.db alerts --limit 20
```

## What Canari Is

- Local canary token leak detector.
- Deterministic scanner using exact token matching.
- Works without calling an LLM.

## What Canari Is Not

- A full security platform.
- A model evaluation engine.
- A governance SaaS.
- An AI-based content classifier.

## Planned / Future Extensions

These exist in the codebase or roadmap, but they are not the core narrative:

- Dashboard and server mode APIs.
- Advanced integrations (OpenAI client patching, chain/runnable wrappers).
- SIEM/compliance/export workflows.
- Threat-intel sharing and related reporting.

Core use case remains local CLI leak detection with deterministic token scanning.

## Maintainer

Maintained by Christopher Holmes Silva.

- X: https://x.com/cholmess
- LinkedIn: https://linkedin.com/in/christopher-holmes-silva

Feedback is welcome from developers shipping LLM applications.
