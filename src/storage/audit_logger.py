"""SQLite Audit Logger for recording deletion actions and enabling 1-click restore/undo.
"""
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

from src.engine.spam_scorer import ClassificationResult

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent

class AuditLogger:
    """Records deleted emails in SQLite and tracks restore operations."""

    def __init__(self, db_path: Path = WORKSPACE_ROOT / "audit_log.db"):
        self.db_path = db_path
        self._init_db()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initializes tables if they do not exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS batches (
                    batch_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    total_messages INTEGER NOT NULL,
                    action_type TEXT NOT NULL,
                    status TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    thread_id TEXT,
                    sender TEXT,
                    sender_email TEXT,
                    subject TEXT,
                    date_str TEXT,
                    score REAL,
                    action TEXT NOT NULL,
                    reason TEXT,
                    trashed_at TEXT NOT NULL,
                    restored_at TEXT,
                    FOREIGN KEY(batch_id) REFERENCES batches(batch_id)
                )
            """)
            conn.commit()

    def record_batch(
        self,
        batch_id: str,
        results: List[ClassificationResult],
        action_type: str = "TRASH",
    ) -> None:
        """Records a batch of deleted messages."""
        now_str = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO batches (batch_id, timestamp, total_messages, action_type, status)
                VALUES (?, ?, ?, ?, ?)
                """,
                (batch_id, now_str, len(results), action_type, "ACTIVE"),
            )

            for r in results:
                cursor.execute(
                    """
                    INSERT INTO audit_entries (
                        batch_id, message_id, thread_id, sender, sender_email,
                        subject, date_str, score, action, reason, trashed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        batch_id,
                        r.message_id,
                        r.thread_id,
                        r.sender,
                        r.sender_email,
                        r.subject,
                        r.date_str,
                        r.score,
                        r.action,
                        r.reason,
                        now_str,
                    ),
                )
            conn.commit()

    def list_batches(self, limit: int = 30) -> List[Dict[str, Any]]:
        """Lists recent deletion batches."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT batch_id, timestamp, total_messages, action_type, status
                FROM batches
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_batch_entries(self, batch_id: str) -> List[Dict[str, Any]]:
        """Retrieves all message records for a specific batch."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, batch_id, message_id, sender, sender_email, subject, date_str, score, action, reason, trashed_at, restored_at
                FROM audit_entries
                WHERE batch_id = ?
                ORDER BY id ASC
                """,
                (batch_id,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def mark_batch_restored(self, batch_id: str) -> None:
        """Updates batch and its records to RESTORED state."""
        now_str = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE batches SET status = 'RESTORED' WHERE batch_id = ?",
                (batch_id,),
            )
            cursor.execute(
                "UPDATE audit_entries SET restored_at = ? WHERE batch_id = ?",
                (now_str, batch_id),
            )
            conn.commit()
