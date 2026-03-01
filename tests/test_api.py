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
    monkeypatch.setattr(leaklens, "_REPORTS_DIR_REAL", None)
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


# ─── GET /api/reports ─────────────────────────────────────────────────────────

def test_list_reports_empty(client, tmp_reports):
    r = client.get("/api/reports")
    assert r.status_code == 200
    assert json.loads(r.data) == []


def test_list_reports_excludes_partial(client, tmp_reports):
    (tmp_reports / "LeakLens_20240101_120000.json").write_text("{}")
    (tmp_reports / "LeakLens_20240101_120000.partial.json").write_text("{}")
    r = client.get("/api/reports")
    names = [f["name"] for f in json.loads(r.data)]
    assert "LeakLens_20240101_120000.json" in names
    assert "LeakLens_20240101_120000.partial.json" not in names


# ─── GET /api/reports/<name> — path traversal ────────────────────────────────

def test_get_report_not_found(client, tmp_reports):
    r = client.get("/api/reports/nonexistent.json")
    assert r.status_code == 404


def test_get_report_path_traversal_blocked(client, tmp_reports):
    r = client.get("/api/reports/../leaklens.py")
    assert r.status_code == 404


def test_get_report_double_dot_blocked(client, tmp_reports):
    r = client.get("/api/reports/../../etc/passwd")
    assert r.status_code == 404


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


# ─── POST /api/scan — basic validation ───────────────────────────────────────

def test_scan_missing_scan_path(client):
    r = client.post("/api/scan", json={})
    assert r.status_code == 400
    assert "scanPath" in json.loads(r.data)["error"]
