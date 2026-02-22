from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from canari.models import AlertEvent, AlertSeverity, CanaryToken, InjectionStrategy, TokenType


class CanaryRegistry:
    def __init__(self, db_path: str = "canari.db"):
        self.db_path = db_path
        self._ensure_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS canary_tokens (
                    id TEXT PRIMARY KEY,
                    token_type TEXT NOT NULL,
                    value TEXT NOT NULL UNIQUE,
                    injection_strategy TEXT NOT NULL,
                    injection_location TEXT NOT NULL,
                    injection_timestamp TEXT NOT NULL,
                    metadata TEXT NOT NULL,
                    active INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_canary_value ON canary_tokens(value)"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alert_events (
                    id TEXT PRIMARY KEY,
                    canary_id TEXT NOT NULL,
                    canary_value TEXT NOT NULL,
                    token_type TEXT NOT NULL,
                    injection_strategy TEXT NOT NULL,
                    injection_location TEXT NOT NULL,
                    injected_at TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    triggered_at TEXT NOT NULL,
                    conversation_id TEXT,
                    output_snippet TEXT NOT NULL,
                    full_output TEXT,
                    session_metadata TEXT NOT NULL,
                    forensic_notes TEXT NOT NULL,
                    detection_surface TEXT NOT NULL,
                    incident_id TEXT,
                    correlation_count INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_alert_triggered_at ON alert_events(triggered_at DESC)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_alert_severity ON alert_events(severity)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_alert_surface ON alert_events(detection_surface)"
            )

    def add(self, token: CanaryToken) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO canary_tokens
                (id, token_type, value, injection_strategy, injection_location,
                 injection_timestamp, metadata, active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    token.id,
                    token.token_type.value,
                    token.value,
                    token.injection_strategy.value,
                    token.injection_location,
                    token.injection_timestamp.isoformat(),
                    json.dumps(token.metadata),
                    1 if token.active else 0,
                ),
            )

    def get_by_id(self, token_id: str) -> CanaryToken | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM canary_tokens WHERE id = ?", (token_id,)
            ).fetchone()
        return self._row_to_token(row) if row else None

    def get_by_value(self, value: str) -> CanaryToken | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM canary_tokens WHERE value = ?", (value,)
            ).fetchone()
        return self._row_to_token(row) if row else None

    def list_active(self) -> list[CanaryToken]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM canary_tokens WHERE active = 1"
            ).fetchall()
        return [self._row_to_token(row) for row in rows]

    def deactivate(self, token_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE canary_tokens SET active = 0 WHERE id = ?", (token_id,)
            )
            return cur.rowcount > 0

    def stats(self) -> dict:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) AS c FROM canary_tokens").fetchone()["c"]
            active = conn.execute(
                "SELECT COUNT(*) AS c FROM canary_tokens WHERE active = 1"
            ).fetchone()["c"]
            by_type_rows = conn.execute(
                "SELECT token_type, COUNT(*) AS c FROM canary_tokens GROUP BY token_type"
            ).fetchall()
            by_strategy_rows = conn.execute(
                "SELECT injection_strategy, COUNT(*) AS c FROM canary_tokens GROUP BY injection_strategy"
            ).fetchall()
        return {
            "total_tokens": total,
            "active_tokens": active,
            "inactive_tokens": total - active,
            "by_type": {row["token_type"]: row["c"] for row in by_type_rows},
            "by_strategy": {row["injection_strategy"]: row["c"] for row in by_strategy_rows},
        }

    def record_alert(self, event: AlertEvent) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO alert_events
                (id, canary_id, canary_value, token_type, injection_strategy, injection_location,
                 injected_at, severity, triggered_at, conversation_id, output_snippet, full_output,
                 session_metadata, forensic_notes, detection_surface, incident_id, correlation_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.id,
                    event.canary_id,
                    event.canary_value,
                    event.token_type.value,
                    event.injection_strategy.value,
                    event.injection_location,
                    event.injected_at.isoformat(),
                    event.severity.value,
                    event.triggered_at.isoformat(),
                    event.conversation_id,
                    event.output_snippet,
                    event.full_output,
                    json.dumps(event.session_metadata),
                    event.forensic_notes,
                    event.detection_surface,
                    event.incident_id,
                    event.correlation_count,
                ),
            )

    def list_alerts(
        self,
        *,
        limit: int = 50,
        severity: str | None = None,
        detection_surface: str | None = None,
        conversation_id: str | None = None,
        incident_id: str | None = None,
    ) -> list[AlertEvent]:
        clauses = []
        params: list = []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if detection_surface:
            clauses.append("detection_surface = ?")
            params.append(detection_surface)
        if conversation_id:
            clauses.append("conversation_id = ?")
            params.append(conversation_id)
        if incident_id:
            clauses.append("incident_id = ?")
            params.append(incident_id)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"""
            SELECT * FROM alert_events
            {where}
            ORDER BY triggered_at DESC
            LIMIT ?
        """
        params.append(max(1, limit))

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row_to_alert(row) for row in rows]

    def alert_stats(self) -> dict:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) AS c FROM alert_events").fetchone()["c"]
            by_severity = conn.execute(
                "SELECT severity, COUNT(*) AS c FROM alert_events GROUP BY severity"
            ).fetchall()
            by_surface = conn.execute(
                "SELECT detection_surface, COUNT(*) AS c FROM alert_events GROUP BY detection_surface"
            ).fetchall()
        return {
            "total_alerts": total,
            "by_severity": {row["severity"]: row["c"] for row in by_severity},
            "by_surface": {row["detection_surface"]: row["c"] for row in by_surface},
        }

    def purge_alerts_older_than(self, *, days: int) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(days=max(0, days))
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM alert_events WHERE triggered_at < ?",
                (cutoff.isoformat(),),
            )
            return cur.rowcount

    @staticmethod
    def _row_to_token(row: sqlite3.Row) -> CanaryToken:
        return CanaryToken(
            id=row["id"],
            token_type=TokenType(row["token_type"]),
            value=row["value"],
            injection_strategy=InjectionStrategy(row["injection_strategy"]),
            injection_location=row["injection_location"],
            injection_timestamp=datetime.fromisoformat(row["injection_timestamp"]),
            metadata=json.loads(row["metadata"]),
            active=bool(row["active"]),
        )

    @staticmethod
    def _row_to_alert(row: sqlite3.Row) -> AlertEvent:
        return AlertEvent(
            id=row["id"],
            canary_id=row["canary_id"],
            canary_value=row["canary_value"],
            token_type=TokenType(row["token_type"]),
            injection_strategy=InjectionStrategy(row["injection_strategy"]),
            injection_location=row["injection_location"],
            injected_at=datetime.fromisoformat(row["injected_at"]),
            severity=AlertSeverity(row["severity"]),
            triggered_at=datetime.fromisoformat(row["triggered_at"]),
            conversation_id=row["conversation_id"],
            output_snippet=row["output_snippet"],
            full_output=row["full_output"],
            session_metadata=json.loads(row["session_metadata"]),
            forensic_notes=row["forensic_notes"],
            detection_surface=row["detection_surface"],
            incident_id=row["incident_id"],
            correlation_count=int(row["correlation_count"]),
        )
