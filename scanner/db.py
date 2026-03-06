"""
LeakLens database helpers — SQLite access layer.

All scan data lives in per-scan databases at:
    <reports_dir>/LeakLens_<scan_id>.db

Schema is applied at connection time by open_db(). Query functions open
read-only URI connections so they are safe to call concurrently with an
active scan writing to the same file.
"""
import datetime
import json
import logging
import os
import sqlite3
import time

_log = logging.getLogger("leaklens.db")

# ─── Schema ───────────────────────────────────────────────────────────────────

DB_SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    scan_path   TEXT,
    scan_date   TEXT,
    scanned     INTEGER DEFAULT 0,
    hits        INTEGER DEFAULT 0,
    completed   INTEGER DEFAULT 0,
    started_at  INTEGER
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT NOT NULL,
    risk_level  TEXT NOT NULL,
    confidence  INTEGER,
    file_name   TEXT,
    full_path   TEXT,
    data        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_scan
    ON findings (scan_id, risk_level);
"""


# ─── Connection helpers ───────────────────────────────────────────────────────

def open_db(path: str) -> sqlite3.Connection:
    """
    Open (or create) a scan database, apply schema, and return the connection.
    Caller is responsible for calling conn.close().
    """
    conn = sqlite3.connect(path)
    conn.executescript(DB_SCHEMA)
    return conn


def open_db_readonly(path: str) -> sqlite3.Connection:
    """Open an existing scan database in read-only mode."""
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


# ─── Write helpers (used by engine.py) ───────────────────────────────────────

def insert_scan(conn: sqlite3.Connection, scan_id: str, scan_path: str,
                started_at: int) -> None:
    """Insert the initial scan record and commit."""
    conn.execute(
        "INSERT OR REPLACE INTO scans (id, scan_path, scan_date, started_at) "
        "VALUES (?, ?, ?, ?)",
        (
            scan_id,
            scan_path,
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            started_at,
        ),
    )
    conn.commit()


def insert_finding(
    conn: sqlite3.Connection,
    scan_id: str,
    risk_level: str,
    confidence: int | None,
    file_name: str | None,
    full_path: str | None,
    data_json: str,
) -> None:
    """Insert a single finding row. Caller is responsible for committing."""
    conn.execute(
        "INSERT INTO findings "
        "(scan_id, risk_level, confidence, file_name, full_path, data) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (scan_id, risk_level, confidence, file_name, full_path, data_json),
    )


def update_scan_complete(conn: sqlite3.Connection, scan_id: str,
                         scanned: int, hits: int) -> None:
    """Mark a scan as completed and record final file/hit counts."""
    conn.execute(
        "UPDATE scans SET scanned=?, hits=?, completed=1 WHERE id=?",
        (scanned, hits, scan_id),
    )
    conn.commit()


# ─── Query helpers (used by leaklens.py route handlers) ──────────────────────

def query_findings(
    db_path: str,
    scan_id: str,
    page: int,
    per_page: int,
    risk: str,
    search: str,
) -> tuple:
    """
    Query paginated findings from a scan database.

    Returns (total: int, findings: list[dict]).
    Raises FileNotFoundError if db_path does not exist.
    Raises sqlite3.Error on database errors.
    """
    if not os.path.isfile(db_path):
        raise FileNotFoundError(f"Scan database not found: {db_path}")

    conn = open_db_readonly(db_path)
    try:
        conditions = ["scan_id = ?"]
        params: list = [scan_id]

        if risk != "ALL":
            conditions.append("risk_level = ?")
            params.append(risk)

        if search:
            conditions.append("(file_name LIKE ? OR full_path LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])

        where = " AND ".join(conditions)

        total = conn.execute(
            f"SELECT COUNT(*) FROM findings WHERE {where}", params
        ).fetchone()[0]

        rows = conn.execute(
            f"SELECT data FROM findings WHERE {where} ORDER BY id LIMIT ? OFFSET ?",
            params + [per_page, page * per_page],
        ).fetchall()

        findings = [json.loads(r["data"]) for r in rows]
        return total, findings
    finally:
        conn.close()


def get_scan_meta(db_path: str, scan_id: str) -> dict | None:
    """
    Return the scan metadata row for scan_id as a dict, or None if not found.
    Raises FileNotFoundError if db_path does not exist.
    """
    if not os.path.isfile(db_path):
        raise FileNotFoundError(f"Scan database not found: {db_path}")

    conn = open_db_readonly(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_all_findings(db_path: str, scan_id: str) -> list:
    """
    Return all findings for a scan as a list of dicts.
    Raises FileNotFoundError if db_path does not exist.
    """
    if not os.path.isfile(db_path):
        raise FileNotFoundError(f"Scan database not found: {db_path}")

    conn = open_db_readonly(db_path)
    try:
        rows = conn.execute(
            "SELECT data FROM findings WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        ).fetchall()
        return [json.loads(r["data"]) for r in rows]
    finally:
        conn.close()


def get_all_scans(reports_dir: str) -> list:
    """
    Read scan metadata from all LeakLens_*.db files in reports_dir.
    Returns list of scan dicts sorted by started_at descending.
    Non-readable databases are skipped with a debug log.
    """
    if not os.path.isdir(reports_dir):
        return []

    scans = []
    for fname in os.listdir(reports_dir):
        if not fname.startswith("LeakLens_") or not fname.endswith(".db"):
            continue
        db_path = os.path.join(reports_dir, fname)
        try:
            conn = open_db_readonly(db_path)
            # Derive scan_id from the filename — more reliable than LIMIT 1 if the
            # DB ever ends up with multiple rows (e.g. after a schema migration).
            scan_id_from_file = fname[len("LeakLens_"):-len(".db")]
            row = conn.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id_from_file,)
            ).fetchone()
            if not row:
                # Fallback: first row in the table (handles hand-created DBs)
                row = conn.execute("SELECT * FROM scans LIMIT 1").fetchone()
            if row:
                scans.append(dict(row))
            conn.close()
        except Exception as e:
            _log.debug("Could not read scan DB %s: %s", db_path, e)

    scans.sort(key=lambda s: s.get("started_at", 0), reverse=True)
    return scans
