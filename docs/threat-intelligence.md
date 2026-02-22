# Threat Intelligence

Canari provides local-first threat intelligence that can optionally federate signatures.

## Local feed

- Build anonymized local feed from recent events.
- Use `threat-feed` for JSON output suitable for internal sharing.

## Opt-in sharing

- Sharing is explicit opt-in and persisted in local settings.
- Use `threat-share show|enable|disable`.

## Import shared signatures

- Import network/community signature bundles with `threat-import`.
- List imported signatures with `network-signatures`.

## Match analysis

- Compare local attack signatures against imported network signatures.
- Use `threat-matches` for overlap and confidence insights.

## Transparency and pattern library

- `threat-transparency` summarizes what was shared/imported/matched.
- `attack-patterns` builds anonymized local attack pattern reports.
