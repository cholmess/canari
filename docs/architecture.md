# Architecture

- `canari.generator`: deterministic synthetic token generation.
- `canari.registry`: local SQLite token registry and alert event journal.
- `canari.injector`: token injection helpers.
- `canari.scanner`: deterministic Aho-Corasick output scanner.
- `canari.alerter`: alert dispatch across channels.
- `canari.adapters`: SDK/runnable adapters (OpenAI client patching, runnable wrapping).
- `canari.detection`: exfiltration-pattern assessment for severity classification.
- `canari.monitor`: outbound HTTP egress monitor for canary credential usage.
- `canari.incidents`: conversation-level event correlation and recent incident snapshots.
- `canari.reporting`: forensic summaries and incident timeline reports.
- `canari.exporter`: JSONL/CSV export for SIEM and offline forensics.
- `canari.cli`: operational CLI for stats, incident reports, and exports.
