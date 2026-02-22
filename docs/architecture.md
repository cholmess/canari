# Architecture

- `canari.generator`: deterministic synthetic token generation.
- `canari.registry`: local SQLite token registry.
- `canari.injector`: token injection helpers.
- `canari.scanner`: deterministic Aho-Corasick output scanner.
- `canari.alerter`: alert dispatch across channels.
- `canari.adapters`: SDK/runnable adapters (OpenAI client patching, runnable wrapping).
