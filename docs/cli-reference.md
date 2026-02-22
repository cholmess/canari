# CLI Reference

Use `canari --db canari.db <command>`.

## Core

- `seed --n N --types api_key,email,credit_card [--tenant T] [--app A]`
- `rotate-canaries --n N --types ... [--tenant T] [--app A]`
- `scan-text --text "..." [--conversation ID]`
- `token-stats`
- `alerts --limit N --offset N [--severity S] [--surface SURFACE] [--conversation ID] [--incident ID] [--tenant T] [--app A] [--since ISO] [--until ISO]`
- `incidents --limit N`
- `incident-report INCIDENT_ID [--tenant T] [--app A]`
- `forensic-summary --limit N`

## Operations

- `alert-stats [--tenant T] [--app A]`
- `alerter-health`
- `incident-replay --incident ID --out PATH`
- `export --format jsonl|csv --out PATH [filters...] [--redact]`
- `backup-db --out PATH`
- `purge-alerts --older-than-days N [--tenant T] [--app A]`
- `policy show`
- `policy set [--min-severity low|medium|high|critical] [--rate-window N --rate-max N] [--retention-days N]`
- `apply-retention [--tenant T] [--app A]`
- `retention-policy list`
- `retention-policy set --retention-days N [--tenant T] [--app A]`
- `retention-policy apply`
- `audit-log --limit N --offset N`
- `doctor`

## Services

- `serve-dashboard --host 127.0.0.1 --port 8080 [--api-token TOKEN] [--check]`
- `serve-api --host 127.0.0.1 --port 8000 [--api-key KEY] [--check]`

## API Keys

- `api-keys add --name NAME --key KEY [--role reader|admin] [--tenant T] [--app A]`
- `api-keys list`
- `api-keys revoke --id ID`
- `api-keys rotate --id ID --new-key KEY`

## SIEM + Compliance

- `siem-export --format json|jsonl|cef [--out PATH] [--limit N] [--tenant T] [--app A]`
- `siem-ingest --in PATH [--source NAME]`
- `siem-external --limit N --offset N`
- `control-plane-export --out PATH`
- `control-plane-import --in PATH [--source NAME] [--dry-run]`
- `control-plane-validate --in PATH`
- `evidence-pack [--limit N] [--tenant T] [--app A] [--out PATH]`
- `incident-dossier --incident ID [--tenant T] [--app A] [--out PATH]`

## Threat Intelligence

- `threat-feed --limit N`
- `threat-share show|enable|disable`
- `threat-import --in PATH [--source NAME]`
- `network-signatures --limit N --offset N`
- `threat-matches --local-limit N --network-limit N`
- `threat-transparency --local-limit N --network-limit N [--out PATH]`
- `attack-patterns --local-limit N [--out PATH]`

## Notes

- Add `--compact` to print single-line JSON.
- All time filters use ISO-8601 UTC timestamps.
