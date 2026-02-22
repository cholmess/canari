# Enterprise Features

Canari includes foundational enterprise controls for multi-team and regulated environments.

## Multi-tenant + Multi-application scope

- Token generation and alert attribution support `tenant_id` and `application_id`.
- Stats, incidents, exports, and SIEM flows can be filtered by tenant/app scope.
- API keys can be scoped by tenant/app with role-based access (`reader`, `admin`).

## Policy and retention

- Persist dispatch policy (minimum severity, rate limits, retention days).
- Define scoped retention profiles per tenant/app and apply in batch.
- Audit trail for policy changes, retention actions, and admin operations.

## SIEM interoperability

- Normalized event export (`siem-export`, `/v1/siem/events`).
- CEF export (`siem-export --format cef`, `/v1/siem/cef`).
- Inbound SIEM event ingestion (`siem-ingest`, `/v1/siem/ingest`) and external event journal.

## Control-plane portability

- Export/import full control-plane bundle for migration between environments.
- Validate bundles before import and support dry-run checks.

## Compliance workflows

- Evidence pack generation for audits (`evidence-pack`, `/v1/compliance/evidence`).
- Incident dossier generation for investigations (`incident-dossier`, `/v1/compliance/incidents/{incident_id}`).

## Security controls

- Optional webhook HMAC signing (`X-Canari-Signature`).
- Dashboard/API token gates and persisted API key lifecycle management.
