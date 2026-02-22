from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

from canari.models import CanaryToken, InjectionStrategy, TokenType


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
