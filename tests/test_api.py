"""
Tests for Flask API endpoints in leaklens.py.
Uses Flask test client — no network, no actual scanning.
"""
import json
import os
import sys
import tempfile
import pytest

# Ensure root is on path so leaklens imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import leaklens
from leaklens import app, REPORTS_DIR


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture
def tmp_reports(monkeypatch, tmp_path):
    """Redirect REPORTS_DIR to a temporary directory for isolation."""
    monkeypatch.setattr(leaklens, "REPORTS_DIR", str(tmp_path))
    return tmp_path


# ─── GET / ────────────────────────────────────────────────────────────────────

def test_index_returns_html(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"LeakLens" in r.data


# ─── GET /api/status ──────────────────────────────────────────────────────────

def test_status_not_scanning(client):
    r = client.get("/api/status")
    assert r.status_code == 200
    data = json.loads(r.data)
    assert data["scanning"] is False
    assert "version" in data


# ─── POST /api/scan/stop ──────────────────────────────────────────────────────

def test_stop_no_active_scan(client):
    r = client.post("/api/scan/stop")
    assert r.status_code == 404


# ─── POST /api/shares ─────────────────────────────────────────────────────────

def test_shares_missing_host(client):
    r = client.post("/api/shares", json={})
    assert r.status_code == 400
    assert "host" in json.loads(r.data)["error"].lower()


def test_shares_invalid_host_characters(client):
    r = client.post("/api/shares", json={"host": "evil; rm -rf /"})
    assert r.status_code == 400


def test_shares_invalid_host_uri(client):
    r = client.post("/api/shares", json={"host": "file:///etc/passwd"})
    assert r.status_code == 400


# ─── GET /api/scans ───────────────────────────────────────────────────────────

def test_list_scans_empty(client, tmp_reports):
    r = client.get("/api/scans")
    assert r.status_code == 200
    assert json.loads(r.data) == []


# ─── GET /api/findings — input validation ────────────────────────────────────

def test_findings_missing_scan_id(client):
    r = client.get("/api/findings")
    assert r.status_code == 400


def test_findings_invalid_scan_id_traversal(client):
    r = client.get("/api/findings?scan_id=../../../etc/passwd")
    assert r.status_code == 400


def test_findings_invalid_scan_id_semicolon(client):
    r = client.get("/api/findings?scan_id=20240101;DROP TABLE findings--")
    assert r.status_code == 400


def test_findings_valid_scan_id_not_found(client, tmp_reports):
    r = client.get("/api/findings?scan_id=20240101_120000")
    assert r.status_code == 404


def test_findings_invalid_page_type(client, tmp_reports):
    r = client.get("/api/findings?scan_id=20240101_120000&page=abc")
    assert r.status_code == 400


# ─── GET /api/scans/<scan_id>/export ─────────────────────────────────────────

def test_export_scan_invalid_id(client):
    r = client.get("/api/scans/../etc/passwd/export")
    assert r.status_code == 404   # Flask 404 before our route fires on path mismatch


def test_export_scan_bad_chars(client):
    r = client.get("/api/scans/bad;id/export")
    assert r.status_code == 400


def test_export_scan_not_found(client, tmp_reports):
    r = client.get("/api/scans/20240101_120000/export")
    assert r.status_code == 404


def test_export_scan_returns_findings(client, tmp_reports):
    """Create a minimal SQLite DB and verify the export endpoint returns it."""
    import sqlite3 as _sq
    scan_id = "20240101_120000"
    db_path = str(tmp_reports / f"LeakLens_{scan_id}.db")
    conn = _sq.connect(db_path)
    conn.executescript("""
        CREATE TABLE scans (id TEXT PRIMARY KEY, scan_path TEXT, scan_date TEXT,
                            scanned INTEGER, hits INTEGER, completed INTEGER, started_at INTEGER);
        CREATE TABLE findings (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT,
                               risk_level TEXT, confidence INTEGER,
                               file_name TEXT, full_path TEXT, data TEXT);
    """)
    conn.execute(
        "INSERT INTO scans VALUES (?,?,?,?,?,?,?)",
        (scan_id, "/tmp/test", "2024-01-01 12:00:00", 5, 1, 1, 0),
    )
    conn.execute(
        "INSERT INTO findings (scan_id, risk_level, confidence, file_name, full_path, data) "
        "VALUES (?,?,?,?,?,?)",
        (scan_id, "HIGH", 9, "id_rsa", "/tmp/test/id_rsa", json.dumps({"riskLevel": "HIGH"})),
    )
    conn.commit()
    conn.close()

    r = client.get(f"/api/scans/{scan_id}/export")
    assert r.status_code == 200
    data = json.loads(r.data)
    assert data["scan_id"] == scan_id
    assert data["scanned"] == 5
    assert len(data["findings"]) == 1
    assert data["findings"][0]["riskLevel"] == "HIGH"


# ─── POST /api/scan — basic validation ───────────────────────────────────────

def test_scan_missing_scan_path(client):
    r = client.post("/api/scan", json={})
    assert r.status_code == 400
    assert "scanPath" in json.loads(r.data)["error"]
