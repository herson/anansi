import json
import os
import sqlite3
import threading
from typing import Any
from datetime import datetime, timezone

DEFAULT_DB_PATH = "anansi.db"


class ScanDatabase:
    def __init__(self, db_path: str | None = None) -> None:
        """
        Args:
            db_path: Path to the SQLite file. Defaults to $ANANSI_DB_PATH, then
                     'anansi.db' in the working directory. Pass ':memory:' for an
                     in-memory DB.
        """
        self.db_path = db_path or os.getenv("ANANSI_DB_PATH") or DEFAULT_DB_PATH
        # Single persistent connection so ':memory:' databases work correctly
        # across multiple method calls. check_same_thread=False allows the
        # background scan thread to write while the web thread reads.
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._lock, self._conn:
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    target       TEXT    NOT NULL,
                    started_at   TEXT    NOT NULL,
                    completed_at TEXT,
                    status       TEXT    NOT NULL DEFAULT 'running',
                    results      TEXT
                )
            """)

    def create_scan(self, target: str) -> int:
        """Insert a new scan record and return its row id."""
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT INTO scans (target, started_at) VALUES (?, ?)",
                (target, datetime.now(timezone.utc).isoformat()),
            )
            if cur.lastrowid is None:
                raise RuntimeError("SQLite did not return an id for the new scan")
            return cur.lastrowid

    def complete_scan(self, scan_id: int, results: list[dict[str, object]]) -> None:
        """Mark scan as completed and persist the findings (in JSON form)."""
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE scans SET status='completed', completed_at=?, results=? WHERE id=?",
                (
                    datetime.now(timezone.utc).isoformat(),
                    json.dumps(results, default=str),
                    scan_id,
                ),
            )

    def fail_scan(self, scan_id: int, error: Exception) -> None:
        """Mark scan as failed and store the error message."""
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE scans SET status='failed', completed_at=?, results=? WHERE id=?",
                (
                    datetime.now(timezone.utc).isoformat(),
                    json.dumps({'error': str(error)}),
                    scan_id,
                ),
            )

    def get_scan(self, scan_id: int) -> dict[str, Any] | None:
        """Return all columns for a single scan, or None if not found."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM scans WHERE id=?", (scan_id,)
            ).fetchone()
            return dict(row) if row else None

    def list_scans(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return recent scans ordered newest-first (no results blob)."""
        with self._lock:
            rows = self._conn.execute(
                """SELECT id, target, started_at, completed_at, status
                   FROM scans ORDER BY id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
