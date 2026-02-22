# Show HN Draft

Show HN: Canari - honeypot tokens for LLM/RAG applications

Prompt injection is OWASP LLM Top 10 #1, but there is still no reliable way to know when an attack actually succeeded. Canari injects synthetic canary tokens (fake API keys, credit cards, emails) into your LLM/RAG context. If an attacker extracts them via prompt injection, Canari alerts immediately with zero false positives because those tokens are synthetic and exist nowhere else.

It takes about 10 lines to integrate with OpenAI-style clients. Canari stores everything locally in SQLite and includes alerting, incident timelines, and forensic summaries.

GitHub: https://github.com/cholmess/canari
PyPI: `pip install canari`
