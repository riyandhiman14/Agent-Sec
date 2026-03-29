from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from ..types import ActionExecutionResult


class AuditStore:
    """SQLite-backed audit store for logging policy decisions.

    Thread-safe: uses check_same_thread=False for file-based databases.
    Supports context manager protocol for automatic cleanup.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or ":memory:"

        if self.db_path != ":memory:":
            # Restrict file permissions for on-disk databases
            old_umask = os.umask(0o077)
            try:
                parent = os.path.dirname(self.db_path)
                if parent:
                    os.makedirs(parent, mode=0o700, exist_ok=True)
                self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            finally:
                os.umask(old_umask)
        else:
            self.conn = sqlite3.connect(self.db_path)

        self.conn.row_factory = sqlite3.Row
        self._init_db()
        self._auto_prune()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self) -> None:
        """Close the database connection."""
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass

    def _init_db(self) -> None:
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS executions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                params TEXT NOT NULL,
                result TEXT,
                policy_status TEXT NOT NULL,
                policy_reason TEXT,
                context TEXT,
                error TEXT,
                outcome TEXT
            )
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_executions_timestamp
            ON executions(timestamp)
        """)
        # Migrate existing databases that don't have the outcome column
        try:
            self.conn.execute("SELECT outcome FROM executions LIMIT 1")
        except sqlite3.OperationalError:
            self.conn.execute("ALTER TABLE executions ADD COLUMN outcome TEXT")
        self.conn.commit()

    def log_execution(self, execution: ActionExecutionResult, context: Optional[Dict[str, Any]] = None, error: Optional[str] = None, outcome: Optional[str] = None) -> None:
        self.conn.execute("""
            INSERT INTO executions (timestamp, action, params, result, policy_status, policy_reason, context, error, outcome)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.utcnow().isoformat(),
            execution.action,
            json.dumps(execution.params, default=str),
            json.dumps(execution.result, default=str) if execution.result is not None else None,
            execution.policy.status.value,
            execution.policy.reason,
            json.dumps(context, default=str) if context else None,
            error,
            outcome,
        ))
        self.conn.commit()

    def get_executions(self, action: Optional[str] = None, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        query = "SELECT * FROM executions"
        params = []

        if action:
            query += " WHERE action = ?"
            params.append(action)

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = self.conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def get_execution_stats(self) -> Dict[str, Any]:
        stats = self.conn.execute("""
            SELECT
                COUNT(*) as total_executions,
                COUNT(CASE WHEN policy_status = 'allow' THEN 1 END) as allowed,
                COUNT(CASE WHEN policy_status = 'block' THEN 1 END) as blocked,
                COUNT(CASE WHEN policy_status = 'review' THEN 1 END) as reviewed,
                COUNT(CASE WHEN error IS NOT NULL THEN 1 END) as errors
            FROM executions
        """).fetchone()

        if stats is None:
            return {"total_executions": 0, "allowed": 0, "blocked": 0, "reviewed": 0, "errors": 0}
        return dict(stats)

    def get_executions_since(
        self, hours: Optional[float] = None, days: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """Get all executions since a time offset. If neither hours nor days given, returns all."""
        query = "SELECT * FROM executions"
        params: List[Any] = []

        if hours is not None or days is not None:
            total_hours = (hours or 0) + (days or 0) * 24
            since = (datetime.utcnow() - timedelta(hours=total_hours)).isoformat()
            query += " WHERE timestamp >= ?"
            params.append(since)

        query += " ORDER BY timestamp DESC LIMIT 100000"
        rows = self.conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def prune(self, days: int = 7) -> int:
        """Delete audit records older than N days. Returns count deleted."""
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
        cursor = self.conn.execute("DELETE FROM executions WHERE timestamp < ?", (cutoff,))
        self.conn.commit()
        return cursor.rowcount

    def clear(self) -> int:
        """Delete ALL audit records. Returns count deleted."""
        cursor = self.conn.execute("DELETE FROM executions")
        self.conn.commit()
        return cursor.rowcount

    def _auto_prune(self) -> None:
        """Auto-prune if AGSEC_AUDIT_RETENTION_DAYS is set."""
        retention = os.environ.get("AGSEC_AUDIT_RETENTION_DAYS")
        if retention is not None:
            try:
                days = int(retention)
                if days > 0:
                    self.prune(days=days)
            except ValueError:
                pass

    def export_to_json(self, file_path: str) -> None:
        executions = self.get_executions(limit=10000)
        # Write with restricted permissions
        old_umask = os.umask(0o077)
        try:
            fd = os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(executions, f, indent=2)
        finally:
            os.umask(old_umask)
