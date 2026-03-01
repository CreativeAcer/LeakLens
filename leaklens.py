#!/usr/bin/env python3
"""
LeakLens — Credential Exposure Scanner
Single entry point: HTTP server + streaming scanner.

Usage:
    python leaklens.py

Opens at http://localhost:3000 (or LEAKLENS_PORT / LEAKLENS_HOST env vars)
"""

import json
import logging
import os
import queue
import re
import sqlite3
import threading

__version__ = "1.1.0"

from flask import Flask, Response, jsonify, request, send_from_directory, stream_with_context

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
_log = logging.getLogger("leaklens")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")

# ─── Active scan state ────────────────────────────────────────────────────────

_scan_lock = threading.Lock()
_active = {
    "running": False,
    "stop_event": threading.Event(),
}

# ─── Helpers ──────────────────────────────────────────────────────────────────

_VALID_SCAN_ID = re.compile(r'^[\w-]+$')
_VALID_HOST    = re.compile(r'^[a-zA-Z0-9._\-]{1,255}$')


def _extract_smb_creds(data: dict):
    """Return (username, password, domain) from a request data dict."""
    return (
        data.get("username") or None,
        data.get("password") or None,
        data.get("domain") or None,
    )


# ─── Static frontend ──────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


# ─── POST /api/scan ───────────────────────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
def scan():
    with _scan_lock:
        if _active["running"]:
            return jsonify({"error": "A scan is already running."}), 409

        data = request.get_json(silent=True) or {}
        scan_path = data.get("scanPath", "").strip()
        max_file_size_mb = int(data.get("maxFileSizeMB", 10))
        workers = max(1, min(16, int(data.get("workers", 8))))
        resume = bool(data.get("resume", False))
        username, password, domain = _extract_smb_creds(data)

        if not scan_path:
            return jsonify({"error": "scanPath is required."}), 400

        max_size = max_file_size_mb * 1024 * 1024

        stop_event = threading.Event()
        _active["running"] = True
        _active["stop_event"] = stop_event

    def generate():
        result_queue = queue.Queue()

        def run():
            try:
                from scanner.engine import scan_path as do_scan
                for event in do_scan(
                    scan_path,
                    max_size,
                    stop_event,
                    username=username,
                    password=password,
                    domain=domain,
                    reports_dir=REPORTS_DIR,
                    workers=workers,
                    resume=resume,
                ):
                    result_queue.put(event)
            except Exception:
                _log.exception("Unhandled error in scan thread")
                result_queue.put({"type": "error", "message": "Scan failed due to an internal error."})
            finally:
                result_queue.put(None)  # sentinel

        worker = threading.Thread(target=run, daemon=True)
        worker.start()

        try:
            while True:
                item = result_queue.get()
                if item is None:
                    break
                yield f"data: {json.dumps(item)}\n\n"
        finally:
            stop_event.set()
            with _scan_lock:
                _active["running"] = False

        yield 'data: {"type": "done"}\n\n'

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ─── POST /api/scan/stop ──────────────────────────────────────────────────────

@app.route("/api/scan/stop", methods=["POST"])
def stop_scan():
    with _scan_lock:
        if not _active["running"]:
            return jsonify({"error": "No active scan."}), 404
        _active["stop_event"].set()
    return jsonify({"stopped": True})


# ─── GET /api/status ──────────────────────────────────────────────────────────

@app.route("/api/status", methods=["GET"])
def status():
    return jsonify({"scanning": _active["running"], "version": __version__})


# ─── POST /api/shares ─────────────────────────────────────────────────────────

@app.route("/api/shares", methods=["POST"])
def list_shares():
    data = request.get_json(silent=True) or {}
    host = data.get("host", "").strip()
    if not host:
        return jsonify({"error": "host is required."}), 400
    if not _VALID_HOST.match(host):
        return jsonify({"error": "Invalid host format."}), 400

    username, password, domain = _extract_smb_creds(data)

    try:
        from scanner.smb import list_shares as smb_list_shares
        shares = smb_list_shares(host, username=username, password=password, domain=domain)
        return jsonify({"shares": shares})
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 503
    except Exception:
        _log.exception("Share enumeration failed for host %s", host)
        return jsonify({"error": "Could not enumerate shares."}), 500


# ─── GET /api/scans ───────────────────────────────────────────────────────────

@app.route("/api/scans", methods=["GET"])
def list_scans():
    """Return metadata for all completed/in-progress SQLite scan databases."""
    if not os.path.isdir(REPORTS_DIR):
        return jsonify([])
    scans = []
    for fname in os.listdir(REPORTS_DIR):
        if not fname.endswith(".db"):
            continue
        db_path = os.path.join(REPORTS_DIR, fname)
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM scans LIMIT 1").fetchone()
            if row:
                scans.append(dict(row))
            conn.close()
        except Exception as e:
            _log.debug("Could not read scan DB %s: %s", db_path, e)
    scans.sort(key=lambda s: s.get("started_at", 0), reverse=True)
    return jsonify(scans)


# ─── GET /api/findings ────────────────────────────────────────────────────────

@app.route("/api/findings", methods=["GET"])
def get_findings():
    """
    Paginated findings query against a scan's SQLite database.

    Query params:
      scan_id   — required; timestamp-based scan ID (e.g. "20240101_120000")
      page      — 0-based page number (default 0)
      per_page  — rows per page, 1–500 (default 100)
      risk      — HIGH | MEDIUM | LOW | ALL (default ALL)
      search    — substring filter on file_name or full_path
    """
    scan_id = request.args.get("scan_id", "").strip()
    if not scan_id:
        return jsonify({"error": "scan_id is required"}), 400
    if not _VALID_SCAN_ID.match(scan_id):
        return jsonify({"error": "Invalid scan_id"}), 400

    try:
        page     = max(0, int(request.args.get("page", 0)))
        per_page = max(1, min(500, int(request.args.get("per_page", 100))))
    except ValueError:
        return jsonify({"error": "page and per_page must be integers"}), 400

    risk   = request.args.get("risk", "ALL").upper()
    search = request.args.get("search", "").strip()

    db_path = os.path.join(REPORTS_DIR, f"LeakLens_{scan_id}.db")
    if not os.path.isfile(db_path):
        return jsonify({"error": "Scan not found"}), 404

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row

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
        conn.close()

        return jsonify({
            "scan_id":  scan_id,
            "total":    total,
            "page":     page,
            "per_page": per_page,
            "findings": findings,
        })
    except Exception:
        _log.exception("Failed to query findings for scan_id %s", scan_id)
        return jsonify({"error": "Failed to query findings."}), 500


# ─── GET /api/scans/<scan_id>/export ─────────────────────────────────────────

@app.route("/api/scans/<scan_id>/export", methods=["GET"])
def export_scan(scan_id):
    """Return all findings for a scan as a single JSON document."""
    if not _VALID_SCAN_ID.match(scan_id):
        return jsonify({"error": "Invalid scan_id"}), 400

    db_path = os.path.join(REPORTS_DIR, f"LeakLens_{scan_id}.db")
    if not os.path.isfile(db_path):
        return jsonify({"error": "Scan not found"}), 404

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        scan_row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not scan_row:
            conn.close()
            return jsonify({"error": "Scan not found"}), 404
        rows = conn.execute(
            "SELECT data FROM findings WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        ).fetchall()
        findings = [json.loads(r["data"]) for r in rows]
        conn.close()
        return jsonify({
            "scan_id":   scan_id,
            "scan_path": scan_row["scan_path"],
            "scan_date": scan_row["scan_date"],
            "scanned":   scan_row["scanned"],
            "hits":      scan_row["hits"],
            "findings":  findings,
        })
    except Exception:
        _log.exception("Failed to export scan %s", scan_id)
        return jsonify({"error": "Failed to export scan."}), 500


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    _host = os.environ.get("LEAKLENS_HOST", "127.0.0.1")
    _port = int(os.environ.get("LEAKLENS_PORT", 3000))
    os.makedirs(REPORTS_DIR, exist_ok=True)
    print(f"\n  LeakLens running at http://{_host}:{_port}\n")
    app.run(host=_host, port=_port, threaded=True, debug=False)
