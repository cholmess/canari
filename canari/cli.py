from __future__ import annotations

import argparse
import json
import sys

from canari import init


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="canari")
    parser.add_argument("--db", default="canari.db", help="Path to canari SQLite DB")
    parser.add_argument("--compact", action="store_true", help="Emit compact JSON without pretty indentation")

    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("token-stats", help="Show token registry stats")
    sub.add_parser("alert-stats", help="Show alert stats")
    p_seed = sub.add_parser("seed", help="Generate and store canary tokens")
    p_seed.add_argument("--n", type=int, default=1)
    p_seed.add_argument("--types", default="api_key")

    p_alerts = sub.add_parser("alerts", help="List recent alerts")
    p_alerts.add_argument("--limit", type=int, default=20)
    p_alerts.add_argument("--severity", default=None)
    p_alerts.add_argument("--surface", default=None)
    p_alerts.add_argument("--conversation", default=None)
    p_alerts.add_argument("--incident", default=None)

    p_incidents = sub.add_parser("incidents", help="List recent incidents")
    p_incidents.add_argument("--limit", type=int, default=20)

    p_report = sub.add_parser("incident-report", help="Show incident timeline report")
    p_report.add_argument("incident_id")
    p_summary = sub.add_parser("forensic-summary", help="Show global forensic summary")
    p_summary.add_argument("--limit", type=int, default=5000)

    p_export = sub.add_parser("export", help="Export alerts to JSONL or CSV")
    p_export.add_argument("--format", choices=["jsonl", "csv"], required=True)
    p_export.add_argument("--out", required=True)
    p_export.add_argument("--limit", type=int, default=1000)
    p_export.add_argument("--severity", default=None)
    p_export.add_argument("--surface", default=None)
    p_export.add_argument("--conversation", default=None)
    p_export.add_argument("--incident", default=None)

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
    if args.cmd == "seed":
        token_types = [t.strip() for t in args.types.split(",") if t.strip()]
        tokens = honey.generate(n_tokens=args.n, token_types=token_types)
        print(encoder([t.model_dump(mode="json") for t in tokens]))
        return 0
    if args.cmd == "alerts":
        alerts = honey.alert_history(
            limit=args.limit,
            severity=args.severity,
            detection_surface=args.surface,
            conversation_id=args.conversation,
            incident_id=args.incident,
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
    if args.cmd == "forensic-summary":
        print(encoder(honey.forensic_summary(limit=args.limit)))
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
            )
        else:
            n = honey.export_alerts_csv(
                args.out,
                limit=args.limit,
                severity=args.severity,
                detection_surface=args.surface,
                conversation_id=args.conversation,
                incident_id=args.incident,
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
