from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..types import ActionExecutionResult


class AuditStore:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or ":memory:"

        # Restrict file permissions for on-disk databases
        if self.db_path != ":memory:":
            parent = os.path.dirname(self.db_path)
            if parent:
                os.makedirs(parent, mode=0o700, exist_ok=True)
            old_umask = os.umask(0o077)
            try:
                self.conn = sqlite3.connect(self.db_path)
            finally:
                os.umask(old_umask)
        else:
            self.conn = sqlite3.connect(self.db_path)

        self.conn.row_factory = sqlite3.Row
        self._init_db()

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
                error TEXT
            )
        """)
        self.conn.commit()

    def log_execution(self, execution: ActionExecutionResult, context: Optional[Dict[str, Any]] = None, error: Optional[str] = None) -> None:
        self.conn.execute("""
            INSERT INTO executions (timestamp, action, params, result, policy_status, policy_reason, context, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.utcnow().isoformat(),
            execution.action,
            json.dumps(execution.params, default=str),
            json.dumps(execution.result, default=str) if execution.result is not None else None,
            execution.policy.status.value,
            execution.policy.reason,
            json.dumps(context) if context else None,
            error
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

    def export_to_json(self, file_path: str) -> None:
        executions = self.get_executions(limit=10000)  # Export last 10k
        with open(file_path, 'w') as f:
            json.dump(executions, f, indent=2)
