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
    sub.add_parser("alert-stats", help="Show alert stats")
    sub.add_parser("alerter-health", help="Show alert dispatcher channel health counters")
    p_audit = sub.add_parser("audit-log", help="Show administrative audit log")
    p_audit.add_argument("--limit", type=int, default=50)
    sub.add_parser("doctor", help="Run local DB/schema diagnostics")
    p_policy = sub.add_parser("policy", help="Show or set persisted dispatch policy")
    p_policy_sub = p_policy.add_subparsers(dest="policy_cmd", required=True)
    p_policy_sub.add_parser("show")
    p_policy_set = p_policy_sub.add_parser("set")
    p_policy_set.add_argument("--min-severity", default=None, choices=["low", "medium", "high", "critical"])
    p_policy_set.add_argument("--rate-window", type=int, default=None)
    p_policy_set.add_argument("--rate-max", type=int, default=None)
    p_seed = sub.add_parser("seed", help="Generate and store canary tokens")
    p_seed.add_argument("--n", type=int, default=1)
    p_seed.add_argument("--types", default="api_key")
    p_rotate = sub.add_parser("rotate-canaries", help="Deactivate active canaries and generate a new set")
    p_rotate.add_argument("--n", type=int, default=3)
    p_rotate.add_argument("--types", default="api_key")

    p_alerts = sub.add_parser("alerts", help="List recent alerts")
    p_alerts.add_argument("--limit", type=int, default=20)
    p_alerts.add_argument("--severity", default=None)
    p_alerts.add_argument("--surface", default=None)
    p_alerts.add_argument("--conversation", default=None)
    p_alerts.add_argument("--incident", default=None)
    p_alerts.add_argument("--tenant", default=None)
    p_alerts.add_argument("--since", default=None, help="ISO8601 lower bound for triggered_at")
    p_alerts.add_argument("--until", default=None, help="ISO8601 upper bound for triggered_at")

    p_incidents = sub.add_parser("incidents", help="List recent incidents")
    p_incidents.add_argument("--limit", type=int, default=20)

    p_report = sub.add_parser("incident-report", help="Show incident timeline report")
    p_report.add_argument("incident_id")
    p_dash = sub.add_parser("serve-dashboard", help="Serve local dashboard and API")
    p_dash.add_argument("--host", default="127.0.0.1")
    p_dash.add_argument("--port", type=int, default=8080)
    p_dash.add_argument("--api-token", default=None, help="Optional token for /api/* auth")
    p_dash.add_argument("--check", action="store_true", help="Start and immediately stop (CI health check)")
    p_replay = sub.add_parser("incident-replay", help="Write one incident timeline to JSONL")
    p_replay.add_argument("--incident", required=True)
    p_replay.add_argument("--out", required=True)
    p_summary = sub.add_parser("forensic-summary", help="Show global forensic summary")
    p_summary.add_argument("--limit", type=int, default=5000)
    p_feed = sub.add_parser("threat-feed", help="Build anonymized local threat-intel feed")
    p_feed.add_argument("--limit", type=int, default=5000)

    p_export = sub.add_parser("export", help="Export alerts to JSONL or CSV")
    p_export.add_argument("--format", choices=["jsonl", "csv"], required=True)
    p_export.add_argument("--out", required=True)
    p_export.add_argument("--limit", type=int, default=1000)
    p_export.add_argument("--severity", default=None)
    p_export.add_argument("--surface", default=None)
    p_export.add_argument("--conversation", default=None)
    p_export.add_argument("--incident", default=None)
    p_export.add_argument("--tenant", default=None)
    p_export.add_argument("--since", default=None, help="ISO8601 lower bound for triggered_at")
    p_export.add_argument("--until", default=None, help="ISO8601 upper bound for triggered_at")
    p_export.add_argument("--redact", action="store_true", help="Redact canary values in exported output")

    p_purge = sub.add_parser("purge-alerts", help="Delete old alert events from local journal")
    p_purge.add_argument("--older-than-days", type=int, required=True)
    p_backup = sub.add_parser("backup-db", help="Backup local Canari SQLite DB")
    p_backup.add_argument("--out", required=True)
    p_scan = sub.add_parser("scan-text", help="Scan arbitrary text for canary leaks")
    p_scan.add_argument("--text", required=True)
    p_scan.add_argument("--conversation", default=None)

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
        print(encoder(honey.alert_stats()))
        return 0
    if args.cmd == "alerter-health":
        print(encoder(honey.alerter_health()))
        return 0
    if args.cmd == "audit-log":
        print(encoder(honey.audit_log(limit=args.limit)))
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
            honey.persist_policy()
            print(encoder({"saved": True, "policy": honey.policy()}))
            return 0
    if args.cmd == "seed":
        token_types = [t.strip() for t in args.types.split(",") if t.strip()]
        tokens = honey.generate(n_tokens=args.n, token_types=token_types)
        print(encoder([t.model_dump(mode="json") for t in tokens]))
        return 0
    if args.cmd == "rotate-canaries":
        token_types = [t.strip() for t in args.types.split(",") if t.strip()]
        report = honey.rotate_canaries(n_tokens=args.n, token_types=token_types)
        print(encoder(report))
        return 0
    if args.cmd == "alerts":
        alerts = honey.alert_history(
            limit=args.limit,
            severity=args.severity,
            detection_surface=args.surface,
            conversation_id=args.conversation,
            incident_id=args.incident,
            since=args.since,
            until=args.until,
            tenant_id=args.tenant,
        )
        print(encoder([a.model_dump(mode="json") for a in alerts]))
        return 0
    if args.cmd == "incidents":
        incidents = honey.recent_incidents(limit=args.limit)
        print(encoder([i.__dict__ for i in incidents]))
        return 0
    if args.cmd == "incident-report":
        print(encoder(honey.incident_report(args.incident_id)))
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
            )
        print(encoder({"exported": n, "path": args.out, "format": args.format}))
        return 0
    if args.cmd == "purge-alerts":
        removed = honey.purge_alerts_older_than(days=args.older_than_days)
        print(encoder({"removed": removed, "older_than_days": args.older_than_days}))
        return 0
    if args.cmd == "backup-db":
        size = honey.backup_db(args.out)
        print(encoder({"path": args.out, "bytes": size}))
        return 0
    if args.cmd == "scan-text":
        events = honey.scan_output(
            args.text,
            context={"conversation_id": args.conversation} if args.conversation else None,
        )
        print(encoder([e.model_dump(mode="json") for e in events]))
        return 0

    print("unknown command", file=sys.stderr)
    return 2
