from __future__ import annotations

import argparse
import json

from canari import init


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="canari")
    parser.add_argument("--db", default="canari.db", help="Path to canari SQLite DB")

    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("token-stats", help="Show token registry stats")
    sub.add_parser("alert-stats", help="Show alert stats")

    p_alerts = sub.add_parser("alerts", help="List recent alerts")
    p_alerts.add_argument("--limit", type=int, default=20)
    p_alerts.add_argument("--severity", default=None)
    p_alerts.add_argument("--surface", default=None)
    p_alerts.add_argument("--conversation", default=None)

    p_incidents = sub.add_parser("incidents", help="List recent incidents")
    p_incidents.add_argument("--limit", type=int, default=20)

    p_report = sub.add_parser("incident-report", help="Show incident timeline report")
    p_report.add_argument("incident_id")

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

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    honey = init(db_path=args.db)
    honey.alerter._channels = []

    if args.cmd == "token-stats":
        print(json.dumps(honey.registry_stats(), indent=2, default=str))
        return 0
    if args.cmd == "alert-stats":
        print(json.dumps(honey.alert_stats(), indent=2, default=str))
        return 0
    if args.cmd == "alerts":
        alerts = honey.alert_history(
            limit=args.limit,
            severity=args.severity,
            detection_surface=args.surface,
            conversation_id=args.conversation,
        )
        print(json.dumps([a.model_dump(mode="json") for a in alerts], indent=2, default=str))
        return 0
    if args.cmd == "incidents":
        incidents = honey.recent_incidents(limit=args.limit)
        print(json.dumps([i.__dict__ for i in incidents], indent=2, default=str))
        return 0
    if args.cmd == "incident-report":
        print(json.dumps(honey.incident_report(args.incident_id), indent=2, default=str))
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
        print(json.dumps({"exported": n, "path": args.out, "format": args.format}))
        return 0
    if args.cmd == "purge-alerts":
        removed = honey.purge_alerts_older_than(days=args.older_than_days)
        print(json.dumps({"removed": removed, "older_than_days": args.older_than_days}))
        return 0

    parser.error("unknown command")
    return 2
