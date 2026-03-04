"""
Tests for scanner/db.py — SQLite access layer.
"""
import json
import os
import sqlite3
import pytest

from scanner.db import (
    open_db,
    open_db_readonly,
    insert_scan,
    update_scan_complete,
    query_findings,
    get_scan_meta,
    get_all_findings,
    get_all_scans,
    DB_SCHEMA,
)


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "LeakLens_test.db")


@pytest.fixture
def conn(db_path):
    c = open_db(db_path)
    yield c
    c.close()


def _seed_scan(conn, scan_id="20240101_120000", scan_path="/tmp/test"):
    insert_scan(conn, scan_id, scan_path, started_at=1000)


def _seed_finding(conn, scan_id="20240101_120000", risk="HIGH", confidence=9,
                  file_name="id_rsa", full_path="/tmp/test/id_rsa"):
    conn.execute(
        "INSERT INTO findings (scan_id, risk_level, confidence, file_name, full_path, data) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (scan_id, risk, confidence, file_name, full_path,
         json.dumps({"riskLevel": risk, "fileName": file_name, "fullPath": full_path})),
    )
    conn.commit()


# ─── open_db / schema ─────────────────────────────────────────────────────────

def test_open_db_creates_tables(db_path):
    conn = open_db(db_path)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    conn.close()
    assert "scans" in tables
    assert "findings" in tables


def test_open_db_creates_index(db_path):
    conn = open_db(db_path)
    indexes = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()}
    conn.close()
    assert "idx_findings_scan" in indexes


def test_open_db_idempotent(db_path):
    # Calling open_db twice should not fail (IF NOT EXISTS guards)
    conn1 = open_db(db_path)
    conn1.close()
    conn2 = open_db(db_path)
    conn2.close()


# ─── insert_scan / update_scan_complete ──────────────────────────────────────

def test_insert_scan(conn, db_path):
    insert_scan(conn, "scan1", "/some/path", started_at=999)
    row = conn.execute("SELECT * FROM scans WHERE id = 'scan1'").fetchone()
    assert row is not None
    assert row[1] == "/some/path"  # scan_path
    assert row[6] == 999           # started_at


def test_update_scan_complete(conn, db_path):
    insert_scan(conn, "scan2", "/path", started_at=0)
    update_scan_complete(conn, "scan2", scanned=100, hits=5)
    row = conn.execute("SELECT scanned, hits, completed FROM scans WHERE id = 'scan2'").fetchone()
    assert row[0] == 100
    assert row[1] == 5
    assert row[2] == 1


# ─── query_findings ───────────────────────────────────────────────────────────

def test_query_findings_basic(conn, db_path):
    _seed_scan(conn)
    _seed_finding(conn, risk="HIGH")
    _seed_finding(conn, risk="LOW", file_name="config.json", full_path="/tmp/test/config.json")

    total, results = query_findings(db_path, "20240101_120000", page=0, per_page=100,
                                    risk="ALL", search="")
    assert total == 2
    assert len(results) == 2


def test_query_findings_risk_filter(conn, db_path):
    _seed_scan(conn)
    _seed_finding(conn, risk="HIGH")
    _seed_finding(conn, risk="LOW", file_name="other.txt", full_path="/tmp/test/other.txt")

    total, results = query_findings(db_path, "20240101_120000", page=0, per_page=100,
                                    risk="HIGH", search="")
    assert total == 1
    assert results[0]["riskLevel"] == "HIGH"


def test_query_findings_search_filter(conn, db_path):
    _seed_scan(conn)
    _seed_finding(conn, file_name="id_rsa", full_path="/tmp/test/id_rsa")
    _seed_finding(conn, risk="LOW", file_name="config.json", full_path="/tmp/test/config.json")

    total, results = query_findings(db_path, "20240101_120000", page=0, per_page=100,
                                    risk="ALL", search="id_rsa")
    assert total == 1
    assert results[0]["fileName"] == "id_rsa"


def test_query_findings_pagination(conn, db_path):
    _seed_scan(conn)
    for i in range(5):
        _seed_finding(conn, risk="HIGH", file_name=f"file{i}.txt",
                      full_path=f"/tmp/test/file{i}.txt")

    total, page0 = query_findings(db_path, "20240101_120000", page=0, per_page=2,
                                   risk="ALL", search="")
    assert total == 5
    assert len(page0) == 2

    _, page1 = query_findings(db_path, "20240101_120000", page=1, per_page=2,
                               risk="ALL", search="")
    assert len(page1) == 2

    _, page2 = query_findings(db_path, "20240101_120000", page=2, per_page=2,
                               risk="ALL", search="")
    assert len(page2) == 1


def test_query_findings_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        query_findings(str(tmp_path / "missing.db"), "scan1", 0, 100, "ALL", "")


# ─── get_scan_meta ────────────────────────────────────────────────────────────

def test_get_scan_meta_found(conn, db_path):
    _seed_scan(conn)
    meta = get_scan_meta(db_path, "20240101_120000")
    assert meta is not None
    assert meta["id"] == "20240101_120000"
    assert meta["scan_path"] == "/tmp/test"


def test_get_scan_meta_not_found(conn, db_path):
    _seed_scan(conn)
    result = get_scan_meta(db_path, "nonexistent")
    assert result is None


def test_get_scan_meta_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        get_scan_meta(str(tmp_path / "missing.db"), "scan1")


# ─── get_all_findings ─────────────────────────────────────────────────────────

def test_get_all_findings(conn, db_path):
    _seed_scan(conn)
    _seed_finding(conn, risk="HIGH")
    _seed_finding(conn, risk="LOW", file_name="other.txt", full_path="/tmp/other.txt")

    results = get_all_findings(db_path, "20240101_120000")
    assert len(results) == 2


def test_get_all_findings_empty(conn, db_path):
    _seed_scan(conn)
    results = get_all_findings(db_path, "20240101_120000")
    assert results == []


# ─── get_all_scans ────────────────────────────────────────────────────────────

def test_get_all_scans_empty_dir(tmp_path):
    result = get_all_scans(str(tmp_path))
    assert result == []


def test_get_all_scans_nonexistent_dir(tmp_path):
    result = get_all_scans(str(tmp_path / "does_not_exist"))
    assert result == []


def test_get_all_scans_multiple_dbs(tmp_path):
    for scan_id, ts in [("scan_a", 100), ("scan_b", 200)]:
        db_p = str(tmp_path / f"LeakLens_{scan_id}.db")
        c = open_db(db_p)
        insert_scan(c, scan_id, f"/path/{scan_id}", started_at=ts)
        c.close()

    results = get_all_scans(str(tmp_path))
    assert len(results) == 2
    # Should be sorted descending by started_at
    assert results[0]["started_at"] == 200
    assert results[1]["started_at"] == 100


def test_get_all_scans_ignores_non_leaklens_dbs(tmp_path):
    # Create a non-LeakLens DB — should be ignored
    other = str(tmp_path / "other.db")
    conn = sqlite3.connect(other)
    conn.close()

    # Create a valid LeakLens DB
    db_p = str(tmp_path / "LeakLens_scan1.db")
    c = open_db(db_p)
    insert_scan(c, "scan1", "/path", started_at=0)
    c.close()

    results = get_all_scans(str(tmp_path))
    assert len(results) == 1
    assert results[0]["id"] == "scan1"
