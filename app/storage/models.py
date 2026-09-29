"""Sample Store + Result Database: SQLite persistence for scans and findings."""
from __future__ import annotations

import sqlite3
import json
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent.parent / "reports" / "analyzer.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    scan_id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    apk_path TEXT NOT NULL,
    package_name TEXT,
    sha256 TEXT,
    created_at REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    source TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    metadata TEXT,
    created_at REAL NOT NULL,
    triage_status TEXT NOT NULL DEFAULT 'open',
    triage_note TEXT,
    FOREIGN KEY (scan_id) REFERENCES samples (scan_id)
);

CREATE TABLE IF NOT EXISTS reports (
    scan_id TEXT PRIMARY KEY,
    report_json TEXT NOT NULL,
    report_html_path TEXT,
    created_at REAL NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES samples (scan_id)
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at REAL NOT NULL
);
"""


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        _migrate(conn)


def _migrate(conn: sqlite3.Connection) -> None:
    """Add columns introduced after the initial schema to existing databases."""
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(findings)").fetchall()}
    if "triage_status" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN triage_status TEXT NOT NULL DEFAULT 'open'")
    if "triage_note" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN triage_note TEXT")

    sample_cols = {row["name"] for row in conn.execute("PRAGMA table_info(samples)").fetchall()}
    if "error_message" not in sample_cols:
        conn.execute("ALTER TABLE samples ADD COLUMN error_message TEXT")
    if "uploaded_by" not in sample_cols:
        conn.execute("ALTER TABLE samples ADD COLUMN uploaded_by TEXT")


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def new_scan_id() -> str:
    return uuid.uuid4().hex[:16]


def create_sample(scan_id: str, filename: str, apk_path: str, uploaded_by: str = "anonymous") -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO samples (scan_id, filename, apk_path, created_at, status, uploaded_by) "
            "VALUES (?, ?, ?, ?, 'pending', ?)",
            (scan_id, filename, apk_path, time.time(), uploaded_by),
        )


def update_sample(scan_id: str, **fields) -> None:
    if not fields:
        return
    cols = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [scan_id]
    with get_conn() as conn:
        conn.execute(f"UPDATE samples SET {cols} WHERE scan_id = ?", values)


def get_sample(scan_id: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM samples WHERE scan_id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None


def list_samples_by_package(package_name: str) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM samples WHERE package_name = ? ORDER BY created_at ASC",
            (package_name,),
        ).fetchall()
        return [dict(r) for r in rows]


def list_distinct_packages() -> list[str]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT DISTINCT package_name FROM samples WHERE package_name IS NOT NULL "
            "ORDER BY package_name"
        ).fetchall()
        return [r["package_name"] for r in rows]


def list_samples_by_user(uploaded_by: str, limit: int = 50) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM samples WHERE uploaded_by = ? ORDER BY created_at DESC LIMIT ?",
            (uploaded_by, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def list_samples(limit: int = 50) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM samples ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def add_finding(scan_id: str, source: str, severity: str, title: str,
                 description: str = "", metadata: dict | None = None) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO findings (scan_id, source, severity, title, description, metadata, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scan_id, source, severity, title, description,
             json.dumps(metadata or {}), time.time()),
        )


def set_finding_triage(finding_id: int, status: str, note: str = "") -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE findings SET triage_status = ?, triage_note = ? WHERE id = ?",
            (status, note, finding_id),
        )


def get_finding(finding_id: int) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["metadata"] = json.loads(d["metadata"] or "{}")
        return d


def get_findings(scan_id: str) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY "
            "CASE severity "
            "WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 "
            "WHEN 'Low' THEN 3 ELSE 4 END",
            (scan_id,),
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["metadata"] = json.loads(d["metadata"] or "{}")
            out.append(d)
        return out


def save_report(scan_id: str, report_json: str, report_html_path: str | None = None) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO reports (scan_id, report_json, report_html_path, created_at) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(scan_id) DO UPDATE SET report_json=excluded.report_json, "
            "report_html_path=excluded.report_html_path, created_at=excluded.created_at",
            (scan_id, report_json, report_html_path, time.time()),
        )


def get_report(scan_id: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM reports WHERE scan_id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None


def create_user(username: str, password_hash: str) -> int:
    """Insert a new user. Raises sqlite3.IntegrityError if the username is taken."""
    with get_conn() as conn:
        cursor = conn.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, password_hash, time.time()),
        )
        return cursor.lastrowid


def get_user_by_username(username: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None


def get_user(user_id: int) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None
