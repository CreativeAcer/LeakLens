"""
LeakLens scanner engine.
Replaces backend/scanner.ps1 — pure Python, handles local paths and UNC/SMB paths.
"""

import os
import datetime
import json
import queue
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
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
from scanner import db as _db


# ─── Module-level constants ────────────────────────────────────────────────────

_CHECKPOINT_EVERY = 1000  # save checkpoint every N files processed
_DB_COMMIT_EVERY  = 50    # commit SQLite batch every N inserts


# ─── Scan configuration ───────────────────────────────────────────────────────

@dataclass
class _ScanConfig:
    """Immutable scan parameters shared across worker threads."""
    root: str
    max_size: int
    stop_event: threading.Event
    is_smb: bool
    smb_port: int
    username: str | None = None
    password: str | None = None
    domain: str | None = None
    suppressions: object = None  # loaded once at scan start
    unc_share_root: str = ""     # empty string for local scans


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

    # Binary-risk files (.kdbx, .pfx, …) are flagged by file type alone; no content scan.
    if not binary_risk:
        if ext in TARGET_EXTENSIONS or (risky_name and ext == ""):
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
    smb_port: int = 445,
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
        register_session(server, username=username, password=password, domain=domain, port=smb_port)
    except Exception as e:
        yield ("error", f"SMB authentication failed for {server}: {e}")
        return

    for item in walk_smb(unc_root, stop_event=stop_event, port=smb_port):
        if stop_event.is_set():
            return
        if item[0] == "__error__":
            yield ("log", f"[ACCESS DENIED] {item[1]}: {item[2]}")
            continue
        smb_path, fname, stat = item
        yield ("smb_file", smb_path, fname, stat, server, share)


# ─── Per-file analysis ────────────────────────────────────────────────────────

def _analyse_item(item: tuple, cfg: _ScanConfig) -> tuple:
    """
    Analyse one file item (local or SMB).
    Returns (finding_dict_or_None, file_path_str).
    """
    if item[0] == "file":
        _, fpath = item
        finding = _check_local_file(fpath, cfg.max_size)
        if finding is None:
            return None, fpath
        pids = [f["id"] for f in finding.get("findingsDetail", [])]
        if is_suppressed(fpath, pids, cfg.suppressions, cfg.root):
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

    # Binary-risk files (.kdbx, .pfx, …) are flagged by file type alone; no content scan.
    if not binary_risk:
        if ext in TARGET_EXTENSIONS or (risky_name and ext == ""):
            if size_bytes <= cfg.max_size:
                content = read_smb_file(smb_path, cfg.max_size, port=cfg.smb_port)
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
        rel_path = smb_path[len(cfg.unc_share_root):].lstrip("\\")
    except Exception:
        rel_path = smb_path

    smb_meta = {
        "smbShare":        cfg.unc_share_root,
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
    if is_suppressed(smb_path, pids, cfg.suppressions, cfg.unc_share_root):
        return None, smb_path

    return finding, smb_path


# ─── Walk thread ──────────────────────────────────────────────────────────────

def _walk(
    cfg: _ScanConfig,
    resume_from: str | None,
    file_q: queue.Queue,
    event_q: queue.Queue,
    workers: int,
) -> None:
    """
    Walk the filesystem and enqueue file items into file_q.
    If resuming, skips files until resume_from path is passed.
    Errors/logs go directly to event_q (never to file_q).
    """
    _skipping = resume_from is not None
    skipped   = 0

    try:
        if cfg.is_smb:
            for ev in _scan_smb(
                cfg.root, cfg.max_size, cfg.stop_event,
                cfg.username, cfg.password, cfg.domain, cfg.smb_port,
            ):
                if cfg.stop_event.is_set():
                    break
                if ev[0] == "error":
                    event_q.put({"type": "error", "message": ev[1]})
                    break
                if ev[0] == "log":
                    event_q.put({"type": "log", "message": ev[1]})
                    continue
                # "smb_file" — resume skip check
                if _skipping:
                    if ev[1] == resume_from:
                        _skipping = False
                    skipped += 1
                    continue
                file_q.put(ev)
        else:
            for ev in _scan_local(cfg.root, cfg.max_size, cfg.stop_event):
                if cfg.stop_event.is_set():
                    break
                if _skipping:
                    if ev[1] == resume_from:
                        _skipping = False
                    skipped += 1
                    continue
                file_q.put(ev)
    finally:
        if skipped > 0:
            event_q.put({
                "type": "log",
                "message": f"Resumed — skipped {skipped} already-scanned files.",
            })
        for _ in range(workers):
            file_q.put(None)  # poison pill per worker


# ─── Worker ───────────────────────────────────────────────────────────────────

def _worker(
    cfg: _ScanConfig,
    file_q: queue.Queue,
    event_q: queue.Queue,
    lock: threading.Lock,
    state: dict,
) -> None:
    """Consume file_q, analyse files, emit events to event_q."""
    while not cfg.stop_event.is_set():
        try:
            item = file_q.get(timeout=1.0)
        except queue.Empty:
            continue

        if item is None:
            break  # poison pill

        fpath   = item[1] if len(item) > 1 else "?"
        finding = None

        try:
            finding, fpath = _analyse_item(item, cfg)
        except Exception as e:
            event_q.put({"type": "log", "message": f"[ERROR] {fpath}: {e}"})

        # Update shared counters exactly once per file
        with lock:
            state["file_count"] += 1
            fc = state["file_count"]
            if finding is not None:
                state["hit_count"] += 1
                hc = state["hit_count"]
            else:
                hc = state["hit_count"]

        if finding is not None:
            event_q.put(finding)

        if fc % 100 == 0 or fc == 1:
            elapsed = max(0.001, time.time() - state["scan_start_time"])
            rate    = round(fc / elapsed, 1)
            event_q.put({
                "type":    "progress",
                "scanned": fc,
                "hits":    hc,
                "current": fpath,
                "rate":    rate,
            })

    event_q.put(("__done__",))


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
    smb_port: int = 445,
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
    is_smb = is_unc_path(root)

    yield {"type": "log", "message": f"Starting scan of: {root} (workers={workers})"}

    if is_smb and not SMB_AVAILABLE:
        yield {"type": "error", "message": "smbprotocol is not installed. Run: pip install smbprotocol"}
        return

    # ── Suppression setup ─────────────────────────────────────────────────────
    if is_smb:
        # .leaklensignore cannot be read from the remote share. Fall back to the
        # process working directory (typically the LeakLens installation root).
        # Place .leaklensignore there if suppression rules are needed for SMB scans.
        cwd = os.getcwd()
        suppressions = load_suppressions(cwd)
        yield {"type": "log", "message": f"SMB scan: .leaklensignore loaded from {cwd}"}
    else:
        if not os.path.exists(root):
            yield {"type": "error", "message": f"Path does not exist or is not accessible: {root}"}
            return
        suppressions = load_suppressions(root)

    # ── Report file paths ─────────────────────────────────────────────────────
    if reports_dir is None:
        reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")

    os.makedirs(reports_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_id   = timestamp
    db_file   = os.path.join(reports_dir, f"LeakLens_{timestamp}.db")
    ckpt_file = _ckpt_path(root, reports_dir)

    # ── SQLite setup ──────────────────────────────────────────────────────────
    _db_conn = _db.open_db(db_file)
    _db.insert_scan(_db_conn, scan_id, root, int(time.time()))
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

    # ── SMB share root used for relative paths ────────────────────────────────
    if is_smb:
        _srv, _shr, _ = parse_unc(root)
        unc_share_root = f"\\\\{_srv}\\{_shr}"
    else:
        unc_share_root = ""

    # ── Scan configuration (shared read-only across threads) ──────────────────
    cfg = _ScanConfig(
        root=root,
        max_size=max_size,
        stop_event=stop_event,
        is_smb=is_smb,
        smb_port=smb_port,
        username=username,
        password=password,
        domain=domain,
        suppressions=suppressions,
        unc_share_root=unc_share_root,
    )

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

    # ── Orchestrate ───────────────────────────────────────────────────────────
    walk_thread = threading.Thread(
        target=_walk,
        args=(cfg, _resume_from, _file_q, _event_q, workers),
        daemon=True,
    )
    walk_thread.start()

    _ckpt_last_scanned = 0
    _ckpt_last_path    = ""

    with ThreadPoolExecutor(max_workers=workers) as executor:
        for _ in range(workers):
            executor.submit(_worker, cfg, _file_q, _event_q, _lock, _state)

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
        _db.update_scan_complete(_db_conn, scan_id, fc, hc)
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
