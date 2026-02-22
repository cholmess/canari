from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from canari import init


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="canari")
    parser.add_argument("--db", default="canari.db", help="Path to canari SQLite DB")
    parser.add_argument("--compact", action="store_true", help="Emit compact JSON without pretty indentation")

    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("token-stats", help="Show token registry stats")
    p_alert_stats = sub.add_parser("alert-stats", help="Show alert stats")
    p_alert_stats.add_argument("--tenant", default=None)
    p_alert_stats.add_argument("--app", default=None)
    sub.add_parser("alerter-health", help="Show alert dispatcher channel health counters")
    p_audit = sub.add_parser("audit-log", help="Show administrative audit log")
    p_audit.add_argument("--limit", type=int, default=50)
    p_audit.add_argument("--offset", type=int, default=0)
    p_keys = sub.add_parser("api-keys", help="Manage persisted API keys")
    p_keys_sub = p_keys.add_subparsers(dest="api_keys_cmd", required=True)
    p_keys_add = p_keys_sub.add_parser("add")
    p_keys_add.add_argument("--name", required=True)
    p_keys_add.add_argument("--key", required=True)
    p_keys_add.add_argument("--role", default="reader")
    p_keys_add.add_argument("--tenant", default=None)
    p_keys_add.add_argument("--app", default=None)
    p_keys_sub.add_parser("list")
    p_keys_revoke = p_keys_sub.add_parser("revoke")
    p_keys_revoke.add_argument("--id", type=int, required=True)
    p_keys_rotate = p_keys_sub.add_parser("rotate")
    p_keys_rotate.add_argument("--id", type=int, required=True)
    p_keys_rotate.add_argument("--new-key", required=True)
    sub.add_parser("doctor", help="Run local DB/schema diagnostics")
    p_policy = sub.add_parser("policy", help="Show or set persisted dispatch policy")
    p_policy_sub = p_policy.add_subparsers(dest="policy_cmd", required=True)
    p_policy_sub.add_parser("show")
    p_policy_set = p_policy_sub.add_parser("set")
    p_policy_set.add_argument("--min-severity", default=None, choices=["low", "medium", "high", "critical"])
    p_policy_set.add_argument("--rate-window", type=int, default=None)
    p_policy_set.add_argument("--rate-max", type=int, default=None)
    p_policy_set.add_argument("--retention-days", type=int, default=None)
    p_apply_ret = sub.add_parser("apply-retention", help="Apply persisted retention policy now")
    p_apply_ret.add_argument("--tenant", default=None)
    p_apply_ret.add_argument("--app", default=None)
    p_rp = sub.add_parser("retention-policy", help="Manage scoped retention policies")
    p_rp_sub = p_rp.add_subparsers(dest="retention_cmd", required=True)
    p_rp_sub.add_parser("list")
    p_rp_apply = p_rp_sub.add_parser("apply")
    p_rp_set = p_rp_sub.add_parser("set")
    p_rp_set.add_argument("--retention-days", type=int, required=True)
    p_rp_set.add_argument("--tenant", default=None)
    p_rp_set.add_argument("--app", default=None)
    p_seed = sub.add_parser("seed", help="Generate and store canary tokens")
    p_seed.add_argument("--n", type=int, default=1)
    p_seed.add_argument("--types", default="api_key")
    p_seed.add_argument("--tenant", default=None)
    p_seed.add_argument("--app", default=None)
    p_rotate = sub.add_parser("rotate-canaries", help="Deactivate active canaries and generate a new set")
    p_rotate.add_argument("--n", type=int, default=3)
    p_rotate.add_argument("--types", default="api_key")
    p_rotate.add_argument("--tenant", default=None)
    p_rotate.add_argument("--app", default=None)

    p_alerts = sub.add_parser("alerts", help="List recent alerts")
    p_alerts.add_argument("--limit", type=int, default=20)
    p_alerts.add_argument("--offset", type=int, default=0)
    p_alerts.add_argument("--severity", default=None)
    p_alerts.add_argument("--surface", default=None)
    p_alerts.add_argument("--conversation", default=None)
    p_alerts.add_argument("--incident", default=None)
    p_alerts.add_argument("--tenant", default=None)
    p_alerts.add_argument("--app", default=None)
    p_alerts.add_argument("--since", default=None, help="ISO8601 lower bound for triggered_at")
    p_alerts.add_argument("--until", default=None, help="ISO8601 upper bound for triggered_at")

    p_incidents = sub.add_parser("incidents", help="List recent incidents")
    p_incidents.add_argument("--limit", type=int, default=20)

    p_report = sub.add_parser("incident-report", help="Show incident timeline report")
    p_report.add_argument("incident_id")
    p_report.add_argument("--tenant", default=None)
    p_report.add_argument("--app", default=None)
    p_dash = sub.add_parser("serve-dashboard", help="Serve local dashboard and API")
    p_dash.add_argument("--host", default="127.0.0.1")
    p_dash.add_argument("--port", type=int, default=8080)
    p_dash.add_argument("--api-token", default=None, help="Optional token for /api/* auth")
    p_dash.add_argument("--check", action="store_true", help="Start and immediately stop (CI health check)")
    p_api = sub.add_parser("serve-api", help="Serve FastAPI backend for dashboard and integrations")
    p_api.add_argument("--host", default="127.0.0.1")
    p_api.add_argument("--port", type=int, default=8000)
    p_api.add_argument("--api-key", default=None, help="Optional API key for /v1/* endpoints")
    p_api.add_argument("--check", action="store_true", help="Validate app can be created, then exit")
    p_replay = sub.add_parser("incident-replay", help="Write one incident timeline to JSONL")
    p_replay.add_argument("--incident", required=True)
    p_replay.add_argument("--out", required=True)
    p_summary = sub.add_parser("forensic-summary", help="Show global forensic summary")
    p_summary.add_argument("--limit", type=int, default=5000)
    p_feed = sub.add_parser("threat-feed", help="Build anonymized local threat-intel feed")
    p_feed.add_argument("--limit", type=int, default=5000)
    p_share = sub.add_parser("threat-share", help="Manage opt-in threat intelligence sharing")
    p_share_sub = p_share.add_subparsers(dest="threat_share_cmd", required=True)
    p_share_sub.add_parser("show")
    p_share_sub.add_parser("enable")
    p_share_sub.add_parser("disable")
    p_import = sub.add_parser("threat-import", help="Import shared threat signature bundle JSON")
    p_import.add_argument("--in", dest="in_path", required=True)
    p_import.add_argument("--source", default="community")
    p_net = sub.add_parser("network-signatures", help="List imported network threat signatures")
    p_net.add_argument("--limit", type=int, default=100)
    p_net.add_argument("--offset", type=int, default=0)
    p_matches = sub.add_parser("threat-matches", help="Show local vs network signature matches")
    p_matches.add_argument("--local-limit", type=int, default=5000)
    p_matches.add_argument("--network-limit", type=int, default=5000)
    p_transparency = sub.add_parser("threat-transparency", help="Show threat-sharing transparency report")
    p_transparency.add_argument("--local-limit", type=int, default=5000)
    p_transparency.add_argument("--network-limit", type=int, default=5000)
    p_transparency.add_argument("--out", default=None)
    p_patterns = sub.add_parser("attack-patterns", help="Show anonymized local attack pattern library")
    p_patterns.add_argument("--local-limit", type=int, default=5000)
    p_patterns.add_argument("--out", default=None)

    p_export = sub.add_parser("export", help="Export alerts to JSONL or CSV")
    p_export.add_argument("--format", choices=["jsonl", "csv"], required=True)
    p_export.add_argument("--out", required=True)
    p_export.add_argument("--limit", type=int, default=1000)
    p_export.add_argument("--severity", default=None)
    p_export.add_argument("--surface", default=None)
    p_export.add_argument("--conversation", default=None)
    p_export.add_argument("--incident", default=None)
    p_export.add_argument("--tenant", default=None)
    p_export.add_argument("--app", default=None)
    p_export.add_argument("--since", default=None, help="ISO8601 lower bound for triggered_at")
    p_export.add_argument("--until", default=None, help="ISO8601 upper bound for triggered_at")
    p_export.add_argument("--redact", action="store_true", help="Redact canary values in exported output")

    p_purge = sub.add_parser("purge-alerts", help="Delete old alert events from local journal")
    p_purge.add_argument("--older-than-days", type=int, required=True)
    p_purge.add_argument("--tenant", default=None)
    p_purge.add_argument("--app", default=None)
    p_backup = sub.add_parser("backup-db", help="Backup local Canari SQLite DB")
    p_backup.add_argument("--out", required=True)
    p_cp_export = sub.add_parser("control-plane-export", help="Export control-plane settings bundle")
    p_cp_export.add_argument("--out", required=True)
    p_cp_import = sub.add_parser("control-plane-import", help="Import control-plane settings bundle")
    p_cp_import.add_argument("--in", dest="in_path", required=True)
    p_cp_import.add_argument("--source", default="control_plane_import")
    p_cp_import.add_argument("--dry-run", action="store_true")
    p_cp_validate = sub.add_parser("control-plane-validate", help="Validate control-plane settings bundle")
    p_cp_validate.add_argument("--in", dest="in_path", required=True)
    p_scan = sub.add_parser("scan-text", help="Scan arbitrary text for canary leaks")
    p_scan.add_argument("--text", required=True)
    p_scan.add_argument("--conversation", default=None)
    p_siem = sub.add_parser("siem-export", help="Export normalized SIEM events as JSON or JSONL")
    p_siem.add_argument("--limit", type=int, default=1000)
    p_siem.add_argument("--tenant", default=None)
    p_siem.add_argument("--app", default=None)
    p_siem.add_argument("--out", default=None, help="Optional output path (.jsonl)")
    p_siem.add_argument("--format", choices=["json", "jsonl", "cef"], default="json")
    p_ingest = sub.add_parser("siem-ingest", help="Ingest external SIEM events from JSON/JSONL file")
    p_ingest.add_argument("--in", dest="in_path", required=True)
    p_ingest.add_argument("--source", default="siem")
    p_external = sub.add_parser("siem-external", help="List ingested external SIEM events")
    p_external.add_argument("--limit", type=int, default=200)
    p_external.add_argument("--offset", type=int, default=0)
    p_evidence = sub.add_parser("evidence-pack", help="Build compliance evidence pack JSON")
    p_evidence.add_argument("--limit", type=int, default=5000)
    p_evidence.add_argument("--tenant", default=None)
    p_evidence.add_argument("--app", default=None)
    p_evidence.add_argument("--out", default=None)
    p_dossier = sub.add_parser("incident-dossier", help="Build incident dossier JSON")
    p_dossier.add_argument("--incident", required=True)
    p_dossier.add_argument("--tenant", default=None)
    p_dossier.add_argument("--app", default=None)
    p_dossier.add_argument("--out", default=None)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    honey = init(db_path=args.db)
    honey.alerter._channels = []
    if args.compact:
        encoder = lambda obj: json.dumps(obj, default=str)
    else:
        encoder = lambda obj: json.dumps(obj, indent=2, default=str)

    if args.cmd == "token-stats":
        print(encoder(honey.registry_stats()))
        return 0
    if args.cmd == "alert-stats":
        print(encoder(honey.alert_stats(tenant_id=args.tenant, application_id=args.app)))
        return 0
    if args.cmd == "alerter-health":
        print(encoder(honey.alerter_health()))
        return 0
    if args.cmd == "audit-log":
        print(encoder(honey.audit_log(limit=args.limit, offset=args.offset)))
        return 0
    if args.cmd == "api-keys":
        if args.api_keys_cmd == "add":
            print(
                encoder(
                    honey.create_api_key(
                        name=args.name,
                        key=args.key,
                        role=args.role,
                        tenant_id=args.tenant,
                        application_id=args.app,
                    )
                )
            )
            return 0
        if args.api_keys_cmd == "list":
            print(encoder(honey.list_api_keys()))
            return 0
        if args.api_keys_cmd == "revoke":
            print(encoder({"id": args.id, "revoked": honey.revoke_api_key(args.id)}))
            return 0
        if args.api_keys_cmd == "rotate":
            print(encoder(honey.rotate_api_key(key_id=args.id, new_key=args.new_key)))
            return 0
    if args.cmd == "doctor":
        print(encoder(honey.doctor()))
        return 0
    if args.cmd == "policy":
        if args.policy_cmd == "show":
            print(encoder(honey.policy()))
            return 0
        if args.policy_cmd == "set":
            if args.min_severity is not None:
                honey.set_min_dispatch_severity(args.min_severity)
            if args.rate_window is not None and args.rate_max is not None:
                honey.set_alert_rate_limit(window_seconds=args.rate_window, max_dispatches=args.rate_max)
            if args.retention_days is not None:
                honey.set_retention_policy(args.retention_days)
            honey.persist_policy()
            print(encoder({"saved": True, "policy": honey.policy()}))
            return 0
    if args.cmd == "apply-retention":
        print(encoder(honey.apply_retention_policy(tenant_id=args.tenant, application_id=args.app)))
        return 0
    if args.cmd == "retention-policy":
        if args.retention_cmd == "list":
            print(encoder(honey.scoped_retention_policies()))
            return 0
        if args.retention_cmd == "set":
            print(
                encoder(
                    honey.set_scoped_retention_policy(
                        retention_days=args.retention_days,
                        tenant_id=args.tenant,
                        application_id=args.app,
                    )
                )
            )
            return 0
        if args.retention_cmd == "apply":
            print(encoder(honey.apply_scoped_retention_policies()))
            return 0
    if args.cmd == "seed":
        token_types = [t.strip() for t in args.types.split(",") if t.strip()]
        tokens = honey.generate(
            n_tokens=args.n,
            token_types=token_types,
            tenant_id=args.tenant,
            application_id=args.app,
        )
        print(encoder([t.model_dump(mode="json") for t in tokens]))
        return 0
    if args.cmd == "rotate-canaries":
        token_types = [t.strip() for t in args.types.split(",") if t.strip()]
        report = honey.rotate_canaries(
            n_tokens=args.n,
            token_types=token_types,
            tenant_id=args.tenant,
            application_id=args.app,
        )
        print(encoder(report))
        return 0
    if args.cmd == "alerts":
        alerts = honey.alert_history(
            limit=args.limit,
            offset=args.offset,
            severity=args.severity,
            detection_surface=args.surface,
            conversation_id=args.conversation,
            incident_id=args.incident,
            since=args.since,
            until=args.until,
            tenant_id=args.tenant,
            application_id=args.app,
        )
        print(encoder([a.model_dump(mode="json") for a in alerts]))
        return 0
    if args.cmd == "incidents":
        incidents = honey.recent_incidents(limit=args.limit)
        print(encoder([i.__dict__ for i in incidents]))
        return 0
    if args.cmd == "incident-report":
        print(
            encoder(
                honey.incident_report(
                    args.incident_id,
                    tenant_id=args.tenant,
                    application_id=args.app,
                )
            )
        )
        return 0
    if args.cmd == "serve-dashboard":
        server = honey.create_dashboard_server(host=args.host, port=args.port, api_token=args.api_token)
        try:
            host, port = server.start()
        except OSError as exc:
            print(encoder({"error": "dashboard_bind_failed", "detail": str(exc)}))
            return 1
        print(encoder({"url": f"http://{host}:{port}", "host": host, "port": port}))
        if args.check:
            server.stop()
            return 0
        try:
            import time

            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            server.stop()
            return 0
    if args.cmd == "serve-api":
        try:
            app = honey.create_fastapi_app(api_key=args.api_key)
        except Exception as exc:
            print(encoder({"error": "fastapi_unavailable", "detail": str(exc)}))
            return 1

        if args.check:
            print(encoder({"ok": True, "app": "fastapi", "host": args.host, "port": args.port}))
            return 0
        try:
            import uvicorn
        except Exception as exc:
            print(encoder({"error": "uvicorn_unavailable", "detail": str(exc)}))
            return 1
        uvicorn.run(app, host=args.host, port=args.port)
        return 0
    if args.cmd == "incident-replay":
        alerts = honey.alert_history(limit=5000, incident_id=args.incident)
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as f:
            for alert in sorted(alerts, key=lambda a: a.triggered_at):
                f.write(json.dumps(alert.model_dump(mode="json"), default=str) + "\n")
        print(encoder({"incident_id": args.incident, "out": args.out, "written": len(alerts)}))
        return 0
    if args.cmd == "forensic-summary":
        print(encoder(honey.forensic_summary(limit=args.limit)))
        return 0
    if args.cmd == "threat-feed":
        print(encoder(honey.local_threat_feed(limit=args.limit)))
        return 0
    if args.cmd == "threat-share":
        if args.threat_share_cmd == "show":
            print(encoder(honey.threat_sharing_status()))
            return 0
        if args.threat_share_cmd == "enable":
            honey.set_threat_sharing_opt_in(True)
            print(encoder(honey.threat_sharing_status()))
            return 0
        if args.threat_share_cmd == "disable":
            honey.set_threat_sharing_opt_in(False)
            print(encoder(honey.threat_sharing_status()))
            return 0
    if args.cmd == "threat-import":
        with Path(args.in_path).open("r", encoding="utf-8") as f:
            payload = json.load(f)
        print(encoder(honey.import_threat_share_bundle(payload, source=args.source)))
        return 0
    if args.cmd == "network-signatures":
        print(encoder(honey.network_signatures(limit=args.limit, offset=args.offset)))
        return 0
    if args.cmd == "threat-matches":
        print(
            encoder(
                honey.network_threat_matches(
                    local_limit=args.local_limit,
                    network_limit=args.network_limit,
                )
            )
        )
        return 0
    if args.cmd == "threat-transparency":
        payload = honey.threat_transparency_report(
            local_limit=args.local_limit,
            network_limit=args.network_limit,
        )
        if args.out:
            out = Path(args.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
            print(encoder({"written": True, "path": args.out}))
            return 0
        print(encoder(payload))
        return 0
    if args.cmd == "attack-patterns":
        payload = honey.attack_pattern_library(local_limit=args.local_limit)
        if args.out:
            out = Path(args.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
            print(encoder({"written": True, "path": args.out}))
            return 0
        print(encoder(payload))
        return 0
    if args.cmd == "export":
        if args.format == "jsonl":
            n = honey.export_alerts_jsonl(
                args.out,
                limit=args.limit,
                severity=args.severity,
                detection_surface=args.surface,
                conversation_id=args.conversation,
                incident_id=args.incident,
                since=args.since,
                until=args.until,
                redact=args.redact,
                tenant_id=args.tenant,
                application_id=args.app,
            )
        else:
            n = honey.export_alerts_csv(
                args.out,
                limit=args.limit,
                severity=args.severity,
                detection_surface=args.surface,
                conversation_id=args.conversation,
                incident_id=args.incident,
                since=args.since,
                until=args.until,
                redact=args.redact,
                tenant_id=args.tenant,
                application_id=args.app,
            )
        print(encoder({"exported": n, "path": args.out, "format": args.format}))
        return 0
    if args.cmd == "purge-alerts":
        removed = honey.purge_alerts_older_than(
            days=args.older_than_days,
            tenant_id=args.tenant,
            application_id=args.app,
        )
        print(
            encoder(
                {
                    "removed": removed,
                    "older_than_days": args.older_than_days,
                    "tenant_id": args.tenant,
                    "application_id": args.app,
                }
            )
        )
        return 0
    if args.cmd == "backup-db":
        size = honey.backup_db(args.out)
        print(encoder({"path": args.out, "bytes": size}))
        return 0
    if args.cmd == "control-plane-export":
        payload = honey.export_control_plane_bundle()
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        print(encoder({"written": True, "path": args.out}))
        return 0
    if args.cmd == "control-plane-import":
        payload = json.loads(Path(args.in_path).read_text(encoding="utf-8"))
        print(encoder(honey.import_control_plane_bundle(payload, source=args.source, dry_run=args.dry_run)))
        return 0
    if args.cmd == "control-plane-validate":
        payload = json.loads(Path(args.in_path).read_text(encoding="utf-8"))
        print(encoder(honey.validate_control_plane_bundle(payload)))
        return 0
    if args.cmd == "scan-text":
        events = honey.scan_output(
            args.text,
            context={"conversation_id": args.conversation} if args.conversation else None,
        )
        print(encoder([e.model_dump(mode="json") for e in events]))
        return 0
    if args.cmd == "siem-export":
        if args.format == "cef":
            rows = honey.siem_cef_events(limit=args.limit, tenant_id=args.tenant, application_id=args.app)
        else:
            rows = honey.siem_events(limit=args.limit, tenant_id=args.tenant, application_id=args.app)
        if args.out:
            out = Path(args.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            with out.open("w", encoding="utf-8") as f:
                if args.format == "json":
                    f.write(json.dumps(rows, indent=2, default=str))
                elif args.format == "jsonl":
                    for row in rows:
                        f.write(json.dumps(row, default=str) + "\n")
                else:
                    for row in rows:
                        f.write(str(row) + "\n")
            print(encoder({"exported": len(rows), "path": args.out, "format": args.format}))
            return 0
        if args.format == "cef":
            print("\n".join(rows))
        else:
            print(encoder(rows))
        return 0
    if args.cmd == "siem-ingest":
        src = Path(args.in_path)
        content = src.read_text(encoding="utf-8")
        events: list[dict]
        if src.suffix.lower() == ".jsonl":
            events = [json.loads(line) for line in content.splitlines() if line.strip()]
        else:
            payload = json.loads(content)
            if isinstance(payload, dict) and isinstance(payload.get("events"), list):
                events = payload["events"]
            elif isinstance(payload, list):
                events = payload
            else:
                events = [payload]
        print(encoder(honey.ingest_external_siem_events(events, source=args.source)))
        return 0
    if args.cmd == "siem-external":
        print(encoder(honey.external_events(limit=args.limit, offset=args.offset)))
        return 0
    if args.cmd == "evidence-pack":
        payload = honey.compliance_evidence_pack(
            limit=args.limit,
            tenant_id=args.tenant,
            application_id=args.app,
        )
        if args.out:
            out = Path(args.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
            print(encoder({"written": True, "path": args.out}))
            return 0
        print(encoder(payload))
        return 0
    if args.cmd == "incident-dossier":
        payload = honey.incident_dossier(
            args.incident,
            tenant_id=args.tenant,
            application_id=args.app,
        )
        if args.out:
            out = Path(args.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
            print(encoder({"written": True, "path": args.out}))
            return 0
        print(encoder(payload))
        return 0

    print("unknown command", file=sys.stderr)
    return 2
