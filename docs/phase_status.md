# Phase Status

## Phase 0 — Foundation
- [x] Python package scaffold (`pyproject.toml`, package modules, tests)
- [x] Core models (`CanaryToken`, `AlertEvent`, enums)
- [x] Token generator for key token types
- [x] SQLite token registry
- [x] Test baseline for generator/registry/scanner

## Phase 1 — MVP Library
- [x] Injection strategies (prompt/context/document-style helpers)
- [x] Output scanning with Aho-Corasick path + deterministic fallback
- [x] Alert dispatcher (webhook/slack/stdout/file/callback)
- [x] Integrations (callables, chain/query/runnable wrappers)
- [x] CLI baseline and examples

## Phase 2 — Detection Engine
- [x] Exfiltration analyzer with severity rules
- [x] Egress HTTP monitor
- [x] Incident correlation across surfaces
- [x] Alert journal persistence and rich filtering
- [x] Forensic reporting and timeline API

## Phase 3 — Dashboard & Ops Visibility
- [x] Local dashboard server + JSON API
- [x] CLI operational commands (stats, incidents, exports, diagnostics)
- [x] Dispatch health metrics and retries
- [x] Time-window filters, replay exports, backup/purge

## Phase 4 — Threat Intelligence (Local)
- [x] Anonymized local threat-signature feed generation
- [x] CLI threat-feed output

## Phase 5 — Enterprise Controls (Foundational)
- [x] Tenant-aware alert attribution/filtering (`tenant_id`)
- [x] Redacted exports for compliance
- [x] Webhook payload signing + verification
- [x] Persisted policy controls and audit log
- [x] Dashboard API token gate

## Current Test Status
- `pytest`: passing (with one sandbox-related dashboard socket test skip)
