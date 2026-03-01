"""
LeakLens scanner engine.
Replaces backend/scanner.ps1 — pure Python, handles local paths and UNC/SMB paths.
"""

import os
import datetime
import json
import queue
import sqlite3
import time
import threading
from concurrent.futures import ThreadPoolExecutor, wait as fut_wait
from typing import Generator

from scanner.patterns import (
    FLAGGED_EXTENSIONS,
    FLAGGED_NAMES,
    FLAGGED_EXACT_NAMES,
    TARGET_EXTENSIONS,
    EXCLUDED_FILENAMES,
)
from scanner.content import scan_content, build_finding
from scanner.suppress import load_suppressions, is_suppressed
from scanner.checkpoint import _ckpt_path, _load_ckpt, _save_ckpt
from scanner.smb import (
    is_unc_path,
    normalize_unc,
    parse_unc,
    register_session,
    walk_smb,
    read_smb_file,
    SMB_AVAILABLE,
)


# ─── Local path scanner ───────────────────────────────────────────────────────

def _check_local_file(path: str, max_size: int):
    """Analyse a single local file. Returns a partial finding dict or None."""
    try:
        stat = os.stat(path)
    except OSError:
        return None

    ext = os.path.splitext(path)[1].lower()
    name = os.path.basename(path).lower()
    name_base = os.path.splitext(name)[0]

    if name in EXCLUDED_FILENAMES:
        return None

    binary_risk = ext in FLAGGED_EXTENSIONS
    risky_name = (
        name in FLAGGED_EXACT_NAMES
        or any(n in name_base for n in FLAGGED_NAMES)
    )

    matched = []

    if binary_risk:
        pass
    elif ext in TARGET_EXTENSIONS or (risky_name and ext == ""):
        if stat.st_size <= max_size:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                matched = scan_content(content, path)
            except OSError:
                pass
    elif not risky_name:
        return None

    if not binary_risk and not risky_name and not matched:
        return None

    last_modified = datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
    last_accessed = datetime.datetime.fromtimestamp(stat.st_atime).strftime("%Y-%m-%d %H:%M")

    owner = ""
    try:
        import pwd
        owner = pwd.getpwuid(stat.st_uid).pw_name
    except Exception:
        pass

    return build_finding(
        path=path,
        ext=ext,
        size_bytes=stat.st_size,
        last_modified=last_modified,
        last_accessed=last_accessed,
        owner=owner,
        matched_patterns=matched,
        risky_name=risky_name,
        binary_risk=binary_risk,
    )


def _scan_local(root: str, max_size: int, stop_event: threading.Event) -> Generator:
    """Walk a local directory and yield file items."""
    for dirpath, dirnames, filenames in os.walk(root):
        if stop_event.is_set():
            return
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for fname in filenames:
            if stop_event.is_set():
                return
            yield ("file", os.path.join(dirpath, fname))


# ─── SMB path scanner ─────────────────────────────────────────────────────────

def _scan_smb(
    unc_root: str,
    max_size: int,
    stop_event: threading.Event,
    username: str = None,
    password: str = None,
    domain: str = None,
) -> Generator:
    """Walk an SMB share and yield file items or error/log events."""
    if not SMB_AVAILABLE:
        yield ("error", "smbprotocol is not installed. Run: pip install smbprotocol")
        return

    server, share, _ = parse_unc(unc_root)
    if not server:
        yield ("error", f"Invalid UNC path: {unc_root}")
        return

    try:
        register_session(server, username=username, password=password, domain=domain)
    except Exception as e:
        yield ("error", f"SMB authentication failed for {server}: {e}")
        return

    for item in walk_smb(unc_root, stop_event=stop_event):
        if stop_event.is_set():
            return
        if item[0] == "__error__":
            yield ("log", f"[ACCESS DENIED] {item[1]}: {item[2]}")
            continue
        smb_path, fname, stat = item
        yield ("smb_file", smb_path, fname, stat, server, share)


# ─── SQLite schema ────────────────────────────────────────────────────────────

_DB_SCHEMA = """
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


# ─── Main entry point ─────────────────────────────────────────────────────────

def scan_path(
    root: str,
    max_size: int,
    stop_event: threading.Event,
    username: str = None,
    password: str = None,
    domain: str = None,
    reports_dir: str = None,
    workers: int = 8,
    resume: bool = False,
) -> Generator:
    """
    Scan root (local path or UNC) and yield JSON-serialisable event dicts.

    Architecture: one walk thread feeds a bounded file_queue; a ThreadPoolExecutor
    with `workers` threads analyses files in parallel; results flow through an
    events_queue back to this generator.

    Findings are written to a SQLite DB (<reports_dir>/LeakLens_<id>.db) as they
    arrive, enabling the paginated /api/findings endpoint to serve historical data.
    A checkpoint file is updated every 1000 files so the scan can be resumed with
    resume=True if interrupted.

    Event types:
      {type: "log",      message: str}
      {type: "progress", scanned: int, hits: int, current: str, rate: float}
      {type: "finding",  ...}
      {type: "summary",  scanned: int, hits: int, scanId: str}
      {type: "error",    message: str}
    """
    _CHECKPOINT_EVERY = 1000  # checkpoint: save every N files processed
    _DB_COMMIT_EVERY  = 50    # SQLite: commit after N inserts

    is_smb = is_unc_path(root)

    yield {"type": "log", "message": f"Starting scan of: {root} (workers={workers})"}

    if is_smb and not SMB_AVAILABLE:
        yield {"type": "error", "message": "smbprotocol is not installed. Run: pip install smbprotocol"}
        return

    # ── Suppression setup ─────────────────────────────────────────────────────
    if is_smb:
        suppressions = load_suppressions(os.getcwd())
    else:
        if not os.path.exists(root):
            yield {"type": "error", "message": f"Path does not exist or is not accessible: {root}"}
            return
        suppressions = load_suppressions(root)

    # ── Report file paths ─────────────────────────────────────────────────────
    if reports_dir is None:
        reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")

    os.makedirs(reports_dir, exist_ok=True)
    timestamp  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_id    = timestamp
    db_file   = os.path.join(reports_dir, f"LeakLens_{timestamp}.db")
    ckpt_file    = _ckpt_path(root, reports_dir)

    # ── SQLite setup ──────────────────────────────────────────────────────────
    _db_conn = sqlite3.connect(db_file)
    _db_conn.executescript(_DB_SCHEMA)
    _db_conn.execute(
        "INSERT OR REPLACE INTO scans (id, scan_path, scan_date, started_at) "
        "VALUES (?, ?, ?, ?)",
        (scan_id, root, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), int(time.time())),
    )
    _db_conn.commit()
    _db_pending = 0

    # ── Checkpoint / resume ───────────────────────────────────────────────────
    _resume_from: str | None = None
    if resume:
        _resume_from, _ckpt_scanned = _load_ckpt(ckpt_file)
        if _resume_from:
            yield {
                "type": "log",
                "message": f"Resuming scan — checkpoint found, skipping up to {_ckpt_scanned} files",
            }

    # SMB share root used for relative paths and suppression checks
    if is_smb:
        _srv, _shr, _ = parse_unc(root)
        unc_share_root = f"\\\\{_srv}\\{_shr}"
    else:
        unc_share_root = ""

    # ── Shared mutable state — ALL mutations guarded by _lock ─────────────────
    _lock  = threading.Lock()
    _state = {
        "file_count":      0,
        "hit_count":       0,
        "scan_start_time": time.time(),
    }

    # ── Queues ────────────────────────────────────────────────────────────────
    _file_q:  queue.Queue = queue.Queue(maxsize=max(workers * 8, 64))
    _event_q: queue.Queue = queue.Queue(maxsize=max(workers * 32, 512))

    # ── Per-file analysis ─────────────────────────────────────────────────────
    def _analyse_item(item: tuple) -> tuple:
        """
        Analyse one file item (local or SMB).
        Returns (finding_dict_or_None, file_path_str).
        """
        if item[0] == "file":
            _, fpath = item
            finding = _check_local_file(fpath, max_size)
            if finding is None:
                return None, fpath
            pids = [f["id"] for f in finding.get("findingsDetail", [])]
            if is_suppressed(fpath, pids, suppressions, root):
                return None, fpath
            return finding, fpath

        # "smb_file"
        _, smb_path, fname, stat, _srv, _shr = item
        if fname.lower() in EXCLUDED_FILENAMES:
            return None, smb_path
        ext       = os.path.splitext(fname)[1].lower()
        name_base = os.path.splitext(fname.lower())[0]
        binary_risk = ext in FLAGGED_EXTENSIONS
        risky_name  = (
            fname.lower() in FLAGGED_EXACT_NAMES
            or any(n in name_base for n in FLAGGED_NAMES)
        )
        size_bytes = stat.st_size if hasattr(stat, "st_size") else 0
        matched    = []

        if binary_risk:
            pass
        elif ext in TARGET_EXTENSIONS or (risky_name and ext == ""):
            if size_bytes <= max_size:
                content = read_smb_file(smb_path, max_size)
                if content:
                    matched = scan_content(content, smb_path)
        elif not risky_name:
            return None, smb_path

        if not binary_risk and not risky_name and not matched:
            return None, smb_path

        try:
            last_modified = datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
            last_accessed = datetime.datetime.fromtimestamp(stat.st_atime).strftime("%Y-%m-%d %H:%M")
        except Exception:
            last_modified = last_accessed = ""

        try:
            rel_path = smb_path[len(unc_share_root):].lstrip("\\")
        except Exception:
            rel_path = smb_path

        smb_meta = {
            "smbShare":        unc_share_root,
            "smbServer":       _srv,
            "smbRelativePath": rel_path,
        }

        finding = build_finding(
            path=smb_path, ext=ext, size_bytes=size_bytes,
            last_modified=last_modified, last_accessed=last_accessed,
            owner="", matched_patterns=matched,
            risky_name=risky_name, binary_risk=binary_risk, smb_meta=smb_meta,
        )
        if finding is None:
            return None, smb_path

        pids = [f["id"] for f in finding.get("findingsDetail", [])]
        if is_suppressed(smb_path, pids, suppressions, unc_share_root):
            return None, smb_path

        return finding, smb_path

    # ── Walk thread ───────────────────────────────────────────────────────────
    def _walk() -> None:
        """
        Walk the filesystem and enqueue file items into _file_q.
        If resuming, skips files until _resume_from path is passed.
        Errors/logs go directly to _event_q (never to _file_q).
        """
        _skipping = _resume_from is not None
        skipped   = 0

        try:
            if is_smb:
                for ev in _scan_smb(root, max_size, stop_event, username, password, domain):
                    if stop_event.is_set():
                        break
                    if ev[0] == "error":
                        _event_q.put({"type": "error", "message": ev[1]})
                        break
                    if ev[0] == "log":
                        _event_q.put({"type": "log", "message": ev[1]})
                        continue
                    # "smb_file" — resume skip check
                    if _skipping:
                        if ev[1] == _resume_from:
                            _skipping = False
                        skipped += 1
                        continue
                    _file_q.put(ev)
            else:
                for ev in _scan_local(root, max_size, stop_event):
                    if stop_event.is_set():
                        break
                    if _skipping:
                        if ev[1] == _resume_from:
                            _skipping = False
                        skipped += 1
                        continue
                    _file_q.put(ev)
        finally:
            if skipped > 0:
                _event_q.put({
                    "type": "log",
                    "message": f"Resumed — skipped {skipped} already-scanned files.",
                })
            for _ in range(workers):
                _file_q.put(None)   # poison pill per worker

    # ── Worker ────────────────────────────────────────────────────────────────
    def _worker() -> None:
        """Consume _file_q, analyse files, emit events to _event_q."""
        while not stop_event.is_set():
            try:
                item = _file_q.get(timeout=1.0)
            except queue.Empty:
                continue

            if item is None:
                break   # poison pill

            fpath   = item[1] if len(item) > 1 else "?"
            finding = None

            try:
                finding, fpath = _analyse_item(item)
            except Exception as e:
                _event_q.put({"type": "log", "message": f"[ERROR] {fpath}: {e}"})

            # Update shared counters exactly once per file
            with _lock:
                _state["file_count"] += 1
                fc = _state["file_count"]
                if finding is not None:
                    _state["hit_count"] += 1
                    hc = _state["hit_count"]
                else:
                    hc = _state["hit_count"]

            if finding is not None:
                _event_q.put(finding)

            if fc % 100 == 0 or fc == 1:
                elapsed = max(0.001, time.time() - _state["scan_start_time"])
                rate    = round(fc / elapsed, 1)
                _event_q.put({
                    "type":    "progress",
                    "scanned": fc,
                    "hits":    hc,
                    "current": fpath,
                    "rate":    rate,
                })

        _event_q.put(("__done__",))

    # ── Orchestrate ───────────────────────────────────────────────────────────
    walk_thread = threading.Thread(target=_walk, daemon=True)
    walk_thread.start()

    _ckpt_last_scanned = 0
    _ckpt_last_path    = ""

    with ThreadPoolExecutor(max_workers=workers) as executor:
        for _ in range(workers):
            executor.submit(_worker)

        done_workers = 0
        fatal_error  = False

        while done_workers < workers:
            item = _event_q.get()

            if isinstance(item, tuple) and item == ("__done__",):
                done_workers += 1
                continue
            if not isinstance(item, dict):
                continue

            ev_type = item.get("type")

            # Persist findings to SQLite
            if ev_type == "finding":
                try:
                    _db_conn.execute(
                        "INSERT INTO findings "
                        "(scan_id, risk_level, confidence, file_name, full_path, data) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            scan_id,
                            item["riskLevel"],
                            item.get("confidence"),
                            item.get("fileName"),
                            item.get("fullPath"),
                            json.dumps(item),
                        ),
                    )
                    _db_pending += 1
                    if _db_pending >= _DB_COMMIT_EVERY:
                        _db_conn.commit()
                        _db_pending = 0
                except Exception:
                    pass

            # Checkpoint on progress events
            elif ev_type == "progress":
                cur     = item.get("current", "")
                scanned = item.get("scanned", 0)
                if cur:
                    _ckpt_last_path = cur
                if (scanned - _ckpt_last_scanned >= _CHECKPOINT_EVERY
                        and _ckpt_last_path):
                    _save_ckpt(ckpt_file, _ckpt_last_path, scanned)
                    _ckpt_last_scanned = scanned

            yield item

            if ev_type == "error":
                fatal_error = True
                stop_event.set()

    walk_thread.join(timeout=5)

    # Commit any remaining SQLite inserts
    if _db_pending > 0:
        try:
            _db_conn.commit()
        except Exception:
            pass

    if fatal_error:
        try:
            _db_conn.close()
        except Exception:
            pass
        return

    with _lock:
        fc = _state["file_count"]
        hc = _state["hit_count"]

    yield {"type": "progress", "scanned": fc, "hits": hc, "current": "", "rate": 0}

    # ── Finalise SQLite scan record ───────────────────────────────────────────
    try:
        _db_conn.execute(
            "UPDATE scans SET scanned=?, hits=?, completed=1 WHERE id=?",
            (fc, hc, scan_id),
        )
        _db_conn.commit()
    except Exception:
        pass

    # Delete checkpoint on successful completion
    try:
        os.remove(ckpt_file)
    except OSError:
        pass

    try:
        _db_conn.close()
    except Exception:
        pass

    yield {
        "type":    "summary",
        "scanned": fc,
        "hits":    hc,
        "scanId":  scan_id,
    }
