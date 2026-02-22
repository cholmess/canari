from __future__ import annotations

import hashlib
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
                    active INTEGER NOT NULL,
                    tenant_id TEXT,
                    application_id TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_canary_value ON canary_tokens(value)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_canary_tenant ON canary_tokens(tenant_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_canary_app ON canary_tokens(application_id)"
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
                    correlation_count INTEGER NOT NULL,
                    tenant_id TEXT,
                    application_id TEXT
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
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_alert_tenant ON alert_events(tenant_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_alert_app ON alert_events(application_id)"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS app_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts DESC)"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    key_hash TEXT NOT NULL UNIQUE,
                    role TEXT NOT NULL,
                    tenant_id TEXT,
                    application_id TEXT,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT,
                    is_active INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(is_active)"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS network_signatures (
                    signature TEXT PRIMARY KEY,
                    token_type TEXT,
                    surface TEXT,
                    severity TEXT,
                    source TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    count INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_network_signatures_count ON network_signatures(count DESC)"
            )
            # Lightweight migration for existing DBs.
            token_cols = {row["name"] for row in conn.execute("PRAGMA table_info(canary_tokens)").fetchall()}
            if "tenant_id" not in token_cols:
                conn.execute("ALTER TABLE canary_tokens ADD COLUMN tenant_id TEXT")
            if "application_id" not in token_cols:
                conn.execute("ALTER TABLE canary_tokens ADD COLUMN application_id TEXT")
            cols = {row["name"] for row in conn.execute("PRAGMA table_info(alert_events)").fetchall()}
            if "tenant_id" not in cols:
                conn.execute("ALTER TABLE alert_events ADD COLUMN tenant_id TEXT")
            if "application_id" not in cols:
                conn.execute("ALTER TABLE alert_events ADD COLUMN application_id TEXT")
            key_cols = {row["name"] for row in conn.execute("PRAGMA table_info(api_keys)").fetchall()}
            if "tenant_id" not in key_cols:
                conn.execute("ALTER TABLE api_keys ADD COLUMN tenant_id TEXT")
            if "application_id" not in key_cols:
                conn.execute("ALTER TABLE api_keys ADD COLUMN application_id TEXT")
            if "last_used_at" not in key_cols:
                conn.execute("ALTER TABLE api_keys ADD COLUMN last_used_at TEXT")

    def set_threat_sharing_opt_in(self, enabled: bool) -> None:
        self.set_setting("threat_intel.opt_in_share", "1" if enabled else "0")

    def threat_sharing_opt_in(self) -> bool:
        return self.get_setting("threat_intel.opt_in_share") == "1"

    def upsert_network_signatures(self, signatures: list[dict], *, source: str = "import") -> int:
        now = datetime.now(timezone.utc).isoformat()
        changed = 0
        with self._connect() as conn:
            for sig in signatures:
                signature = (sig.get("signature") or "").strip()
                if not signature:
                    continue
                count = max(1, int(sig.get("count", 1)))
                token_type = sig.get("token_type")
                surface = sig.get("surface")
                severity = sig.get("severity")
                conn.execute(
                    """
                    INSERT INTO network_signatures
                    (signature, token_type, surface, severity, source, first_seen, last_seen, count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(signature) DO UPDATE SET
                        token_type = COALESCE(excluded.token_type, network_signatures.token_type),
                        surface = COALESCE(excluded.surface, network_signatures.surface),
                        severity = COALESCE(excluded.severity, network_signatures.severity),
                        source = excluded.source,
                        last_seen = excluded.last_seen,
                        count = network_signatures.count + excluded.count
                    """,
                    (signature, token_type, surface, severity, source, now, now, count),
                )
                changed += 1
        return changed

    def get_network_signature(self, signature: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT signature, token_type, surface, severity, source, first_seen, last_seen, count
                FROM network_signatures
                WHERE signature = ?
                """,
                (signature,),
            ).fetchone()
        if not row:
            return None
        return {
            "signature": row["signature"],
            "token_type": row["token_type"],
            "surface": row["surface"],
            "severity": row["severity"],
            "source": row["source"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "count": int(row["count"]),
        }

    def list_network_signatures(self, *, limit: int = 500, offset: int = 0) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT signature, token_type, surface, severity, source, first_seen, last_seen, count
                FROM network_signatures
                ORDER BY count DESC, last_seen DESC, signature ASC
                LIMIT ? OFFSET ?
                """,
                (max(1, limit), max(0, offset)),
            ).fetchall()
        return [
            {
                "signature": row["signature"],
                "token_type": row["token_type"],
                "surface": row["surface"],
                "severity": row["severity"],
                "source": row["source"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "count": int(row["count"]),
            }
            for row in rows
        ]

    def add(self, token: CanaryToken) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO canary_tokens
                (id, token_type, value, injection_strategy, injection_location,
                 injection_timestamp, metadata, active, tenant_id, application_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    token.tenant_id,
                    token.application_id,
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

    def list_active(
        self,
        *,
        tenant_id: str | None = None,
        application_id: str | None = None,
    ) -> list[CanaryToken]:
        if not tenant_id and not application_id:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM canary_tokens WHERE active = 1"
                ).fetchall()
            return [self._row_to_token(row) for row in rows]

        clauses = ["active = 1"]
        params: list = []
        if tenant_id:
            clauses.append("(tenant_id IS NULL OR tenant_id = '' OR tenant_id = ?)")
            params.append(tenant_id)
        if application_id:
            clauses.append("(application_id IS NULL OR application_id = '' OR application_id = ?)")
            params.append(application_id)
        sql = f"SELECT * FROM canary_tokens WHERE {' AND '.join(clauses)}"
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
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
                 session_metadata, forensic_notes, detection_surface, incident_id, correlation_count, tenant_id, application_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    event.tenant_id,
                    event.application_id,
                ),
            )

    def list_alerts(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        severity: str | None = None,
        detection_surface: str | None = None,
        conversation_id: str | None = None,
        incident_id: str | None = None,
        since: str | None = None,
        until: str | None = None,
        tenant_id: str | None = None,
        application_id: str | None = None,
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
        if since:
            clauses.append("triggered_at >= ?")
            params.append(since)
        if until:
            clauses.append("triggered_at <= ?")
            params.append(until)
        if tenant_id:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)
        if application_id:
            clauses.append("application_id = ?")
            params.append(application_id)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"""
            SELECT * FROM alert_events
            {where}
            ORDER BY triggered_at DESC
            LIMIT ?
            OFFSET ?
        """
        params.append(max(1, limit))
        params.append(max(0, offset))

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row_to_alert(row) for row in rows]

    def alert_stats(self, *, tenant_id: str | None = None, application_id: str | None = None) -> dict:
        clauses = []
        params: list = []
        if tenant_id:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)
        if application_id:
            clauses.append("application_id = ?")
            params.append(application_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        with self._connect() as conn:
            total = conn.execute(f"SELECT COUNT(*) AS c FROM alert_events {where}", params).fetchone()["c"]
            by_severity = conn.execute(
                f"SELECT severity, COUNT(*) AS c FROM alert_events {where} GROUP BY severity",
                params,
            ).fetchall()
            by_surface = conn.execute(
                f"SELECT detection_surface, COUNT(*) AS c FROM alert_events {where} GROUP BY detection_surface",
                params,
            ).fetchall()
            by_token_type = conn.execute(
                f"SELECT token_type, COUNT(*) AS c FROM alert_events {where} GROUP BY token_type",
                params,
            ).fetchall()
            by_tenant = conn.execute(
                (
                    f"SELECT tenant_id, COUNT(*) AS c FROM alert_events {where} "
                    "AND tenant_id IS NOT NULL AND tenant_id != '' GROUP BY tenant_id"
                )
                if where
                else "SELECT tenant_id, COUNT(*) AS c FROM alert_events WHERE tenant_id IS NOT NULL AND tenant_id != '' GROUP BY tenant_id",
                params,
            ).fetchall()
            by_application = conn.execute(
                (
                    f"SELECT application_id, COUNT(*) AS c FROM alert_events {where} "
                    "AND application_id IS NOT NULL AND application_id != '' GROUP BY application_id"
                )
                if where
                else "SELECT application_id, COUNT(*) AS c FROM alert_events WHERE application_id IS NOT NULL AND application_id != '' GROUP BY application_id",
                params,
            ).fetchall()
            top_conversations = conn.execute(
                (
                    f"SELECT conversation_id, COUNT(*) AS c FROM alert_events {where} "
                    "AND conversation_id IS NOT NULL AND conversation_id != '' "
                    "GROUP BY conversation_id ORDER BY c DESC, conversation_id ASC LIMIT 5"
                )
                if where
                else (
                    "SELECT conversation_id, COUNT(*) AS c FROM alert_events "
                    "WHERE conversation_id IS NOT NULL AND conversation_id != '' "
                    "GROUP BY conversation_id ORDER BY c DESC, conversation_id ASC LIMIT 5"
                ),
                params,
            ).fetchall()
        return {
            "total_alerts": total,
            "by_severity": {row["severity"]: row["c"] for row in by_severity},
            "by_surface": {row["detection_surface"]: row["c"] for row in by_surface},
            "by_token_type": {row["token_type"]: row["c"] for row in by_token_type},
            "by_tenant": {row["tenant_id"]: row["c"] for row in by_tenant},
            "by_application": {row["application_id"]: row["c"] for row in by_application},
            "top_conversations": [
                {"conversation_id": row["conversation_id"], "count": row["c"]}
                for row in top_conversations
            ],
        }

    def purge_alerts_older_than(
        self,
        *,
        days: int,
        tenant_id: str | None = None,
        application_id: str | None = None,
    ) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(days=max(0, days))
        clauses = ["triggered_at < ?"]
        params: list = [cutoff.isoformat()]
        if tenant_id:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)
        if application_id:
            clauses.append("application_id = ?")
            params.append(application_id)
        where = " AND ".join(clauses)
        with self._connect() as conn:
            cur = conn.execute(
                f"DELETE FROM alert_events WHERE {where}",
                params,
            )
            return cur.rowcount

    def backup_to(self, path: str) -> int:
        dest = Path(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as src_conn:
            with sqlite3.connect(str(dest)) as dest_conn:
                src_conn.backup(dest_conn)
        return dest.stat().st_size

    def set_setting(self, key: str, value: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def get_setting(self, key: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def settings(self) -> dict[str, str]:
        with self._connect() as conn:
            rows = conn.execute("SELECT key, value FROM app_settings").fetchall()
        return {row["key"]: row["value"] for row in rows}

    def record_audit(self, action: str, details: dict) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO audit_events (ts, action, details) VALUES (?, ?, ?)",
                (
                    datetime.now(timezone.utc).isoformat(),
                    action,
                    json.dumps(details),
                ),
            )

    def list_audit(self, limit: int = 100, offset: int = 0) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT ts, action, details FROM audit_events ORDER BY ts DESC LIMIT ? OFFSET ?",
                (max(1, limit), max(0, offset)),
            ).fetchall()
        return [
            {"ts": row["ts"], "action": row["action"], "details": json.loads(row["details"])}
            for row in rows
        ]

    def create_api_key(
        self,
        *,
        name: str,
        key: str,
        role: str = "reader",
        tenant_id: str | None = None,
        application_id: str | None = None,
    ) -> dict:
        key_hash = self._hash_key(key)
        created_at = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO api_keys (name, key_hash, role, tenant_id, application_id, created_at, last_used_at, is_active)
                VALUES (?, ?, ?, ?, ?, ?, NULL, 1)
                """,
                (name, key_hash, role, tenant_id, application_id, created_at),
            )
            key_id = cur.lastrowid
        return {
            "id": key_id,
            "name": name,
            "role": role,
            "tenant_id": tenant_id,
            "application_id": application_id,
            "last_used_at": None,
            "active": True,
            "created_at": created_at,
        }

    def list_api_keys(self, *, include_inactive: bool = True) -> list[dict]:
        where = "" if include_inactive else "WHERE is_active = 1"
        sql = (
            "SELECT id, name, role, tenant_id, application_id, created_at, last_used_at, is_active "
            f"FROM api_keys {where} ORDER BY id ASC"
        )
        with self._connect() as conn:
            rows = conn.execute(sql).fetchall()
        return [
            {
                "id": row["id"],
                "name": row["name"],
                "role": row["role"],
                "tenant_id": row["tenant_id"],
                "application_id": row["application_id"],
                "created_at": row["created_at"],
                "last_used_at": row["last_used_at"],
                "active": bool(row["is_active"]),
            }
            for row in rows
        ]

    def revoke_api_key(self, key_id: int) -> bool:
        with self._connect() as conn:
            cur = conn.execute("UPDATE api_keys SET is_active = 0 WHERE id = ?", (key_id,))
            return cur.rowcount > 0

    def verify_api_key(self, key: str) -> dict | None:
        key_hash = self._hash_key(key)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, name, role, tenant_id, application_id, created_at, last_used_at, is_active FROM api_keys WHERE key_hash = ? AND is_active = 1",
                (key_hash,),
            ).fetchone()
        if not row:
            return None
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (now, row["id"]))
        return {
            "id": row["id"],
            "name": row["name"],
            "role": row["role"],
            "tenant_id": row["tenant_id"],
            "application_id": row["application_id"],
            "created_at": row["created_at"],
            "last_used_at": now,
            "active": bool(row["is_active"]),
        }

    def rotate_api_key(self, *, key_id: int, new_key: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, name, role, tenant_id, application_id, is_active FROM api_keys WHERE id = ?",
                (key_id,),
            ).fetchone()
        if not row:
            return None

        created = self.create_api_key(
            name=row["name"],
            key=new_key,
            role=row["role"],
            tenant_id=row["tenant_id"],
            application_id=row["application_id"],
        )
        old_revoked = self.revoke_api_key(key_id)
        return {"old_key_revoked": old_revoked, "new_key": created}

    @staticmethod
    def _hash_key(key: str) -> str:
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    def doctor(self) -> dict:
        checks = {
            "tables": {"canary_tokens": False, "alert_events": False},
            "writable": False,
        }
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            names = {row["name"] for row in rows}
            checks["tables"]["canary_tokens"] = "canary_tokens" in names
            checks["tables"]["alert_events"] = "alert_events" in names

            try:
                conn.execute("CREATE TABLE IF NOT EXISTS __canari_doctor_tmp (id INTEGER)")
                conn.execute("DROP TABLE __canari_doctor_tmp")
                checks["writable"] = True
            except Exception:
                checks["writable"] = False

        ok = all(checks["tables"].values()) and checks["writable"]
        return {"ok": ok, "db_path": self.db_path, "checks": checks}

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
            tenant_id=row["tenant_id"],
            application_id=row["application_id"],
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
            tenant_id=row["tenant_id"],
            application_id=row["application_id"],
        )
