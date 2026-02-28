"""
LeakLens scanner engine.
Replaces backend/scanner.ps1 — pure Python, handles local paths and UNC/SMB paths.
"""

import os
import pathlib
import re
import fnmatch
import datetime
import json
import queue
import time
import threading
from concurrent.futures import ThreadPoolExecutor, wait as fut_wait
from typing import Generator

from scanner.patterns import (
    COMPILED_PATTERNS,
    FLAGGED_EXTENSIONS,
    FLAGGED_NAMES,
    FLAGGED_EXACT_NAMES,
    TARGET_EXTENSIONS,
    PLACEHOLDER_VALUES,
    DOCS_DIRS,
    HASH_PATTERN_IDS,
)
from scanner.smb import (
    is_unc_path,
    normalize_unc,
    parse_unc,
    register_session,
    walk_smb,
    read_smb_file,
    SMB_AVAILABLE,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def get_risk_level(confidence: int) -> str:
    if confidence >= 8:
        return "HIGH"
    if confidence >= 5:
        return "MEDIUM"
    return "LOW"


def is_placeholder(value: str) -> bool:
    v = value.strip().lower().strip("\"'`")
    return (
        v in PLACEHOLDER_VALUES
        or v.startswith("<")
        or v.startswith("${")
        or v.startswith("%(")
        or v.startswith("{{")
        or len(v) < 4
        or bool(re.match(r"^\*+$", v))
        or bool(re.match(r"^x+$", v))
    )


def is_placeholder_match(match_str: str) -> bool:
    """
    Post-match filter applied to every pattern result.
    Tries to extract the value portion (after = or :) and check it against
    PLACEHOLDER_VALUES — catches noise that inline lookaheads don't cover.
    """
    m = re.search(r'[=:]\s*["\']?([^\s"\'<>{}]{4,})', match_str)
    if not m:
        return False
    return is_placeholder(m.group(1))


def is_docs_path(path: str) -> bool:
    """
    Return True if any exact path segment matches a docs/examples directory name.
    Uses pathlib to avoid substring false positives (e.g. 'docs_archive' should not match).
    """
    parts = pathlib.Path(path.replace("\\", "/")).parts
    return any(part.lower() in DOCS_DIRS for part in parts)


# ─── Suppression (.leaklensignore) ────────────────────────────────────────────

def load_suppressions(root: str) -> dict:
    """
    Parse .leaklensignore from the scan root.
    Returns {'global': [...], 'patterns': {pattern_id: [...]}}
    """
    suppressions = {"global": [], "patterns": {}}
    ignore_file = os.path.join(root, ".leaklensignore")
    if not os.path.exists(ignore_file):
        return suppressions

    current_section = None
    try:
        with open(ignore_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("[") and line.endswith("]"):
                    current_section = line[1:-1]
                    suppressions["patterns"].setdefault(current_section, [])
                elif current_section:
                    suppressions["patterns"][current_section].append(line)
                else:
                    suppressions["global"].append(line)
    except OSError:
        pass

    return suppressions


def is_suppressed(path: str, pattern_ids: list, suppressions: dict, root: str) -> bool:
    """Return True if this finding should be suppressed per .leaklensignore."""
    try:
        rel = os.path.relpath(path, root).replace("\\", "/")
    except ValueError:
        rel = path.replace("\\", "/")

    for glob_pat in suppressions["global"]:
        if fnmatch.fnmatch(rel, glob_pat):
            return True

    for pid in pattern_ids:
        for glob_pat in suppressions["patterns"].get(pid, []):
            if fnmatch.fnmatch(rel, glob_pat):
                return True

    return False


# ─── Content scanning ─────────────────────────────────────────────────────────

def scan_content(content: str, path: str) -> list:
    """
    Match all content patterns against the file text.
    Returns a list of matched pattern dicts (id, name, confidence, risk,
    matchLine, matchSnippet, matchCount, allMatchLines).
    Uses pre-compiled patterns and re.finditer() to capture every occurrence.
    Applies confidence adjustments for docs paths and placeholder values.
    """
    in_docs = is_docs_path(path)
    lines = content.split('\n')
    matched = []

    for pattern in COMPILED_PATTERNS:
        try:
            hit_matches = []
            for m in pattern["regex"].finditer(content):
                # Global post-match placeholder filter
                if is_placeholder_match(m.group(0)):
                    continue
                line_num = content[:m.start()].count('\n') + 1
                raw_line = lines[line_num - 1].strip() if line_num <= len(lines) else m.group(0)
                snippet = raw_line[:120] + ('…' if len(raw_line) > 120 else '')
                hit_matches.append({"line": line_num, "snippet": snippet})
        except re.error:
            continue

        if not hit_matches:
            continue

        conf = pattern["confidence"]

        # Reduce confidence for docs/examples directories
        if in_docs:
            conf = max(1, conf - 3)

        matched.append({
            "id": pattern["id"],
            "name": pattern["name"],
            "confidence": conf,
            "risk": get_risk_level(conf),
            "matchLine": hit_matches[0]["line"],
            "matchSnippet": hit_matches[0]["snippet"],
            "matchCount": len(hit_matches),
            "allMatchLines": [h["line"] for h in hit_matches],
        })

    return matched


# ─── Per-file check ───────────────────────────────────────────────────────────

def build_finding(
    path: str,
    ext: str,
    size_bytes: int,
    last_modified: str,
    last_accessed: str,
    owner: str,
    matched_patterns: list,
    risky_name: bool,
    binary_risk: bool,
    smb_meta: dict = None,
) -> dict:
    """Assemble a finding dict from the per-file analysis."""
    all_findings = list(matched_patterns)

    if binary_risk:
        all_findings.insert(0, {
            "id": "sensitive_file_type",
            "name": f"Sensitive file type ({ext})",
            "confidence": 8,
            "risk": "HIGH",
        })
    if risky_name:
        all_findings.append({
            "id": "risky_filename",
            "name": "Suspicious filename",
            "confidence": 5,
            "risk": "MEDIUM",
        })

    if not all_findings:
        return None

    max_conf = max(f["confidence"] for f in all_findings)
    overall_risk = get_risk_level(max_conf)

    # Flag hash-only findings with a note
    non_hash = [f for f in all_findings
                if f["id"] not in HASH_PATTERN_IDS and f["id"] != "risky_filename"]
    hash_only = (
        not non_hash
        and any(f["id"] in HASH_PATTERN_IDS for f in all_findings)
    )
    if hash_only:
        overall_risk = "LOW"
        max_conf = min(max_conf, 4)

    finding = {
        "type": "finding",
        "riskLevel": overall_risk,
        "confidence": max_conf,
        "fileName": os.path.basename(path),
        "fullPath": path,
        "extension": ext,
        "sizeKB": round(size_bytes / 1024, 1),
        "lastModified": last_modified,
        "lastAccessed": last_accessed,
        "owner": owner,
        "riskyFilename": risky_name,
        "hashOnly": hash_only,
        "findings": " | ".join(f["name"] for f in all_findings),
        "findingsList": [f["name"] for f in all_findings],
        "findingsDetail": all_findings,
    }

    if hash_only:
        finding["note"] = (
            "Hash strings detected — verify these are credential hashes "
            "and not integrity checksums."
        )

    if smb_meta:
        finding.update(smb_meta)

    return finding


# ─── Local path scanner ───────────────────────────────────────────────────────

def _check_local_file(path: str, max_size: int) -> dict | None:
    """Analyse a single local file. Returns a partial finding dict or None."""
    try:
        stat = os.stat(path)
    except OSError:
        return None

    ext = os.path.splitext(path)[1].lower()
    name = os.path.basename(path).lower()
    name_base = os.path.splitext(name)[0]

    binary_risk = ext in FLAGGED_EXTENSIONS
    risky_name = (
        name in FLAGGED_EXACT_NAMES
        or any(n in name_base for n in FLAGGED_NAMES)
    )

    matched = []

    if binary_risk:
        pass  # handled in build_finding
    elif ext in TARGET_EXTENSIONS or (risky_name and ext == ""):
        # Also content-scan extensionless files with risky names (.env, id_rsa, etc.)
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

    # Timestamps
    last_modified = datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
    last_accessed = datetime.datetime.fromtimestamp(stat.st_atime).strftime("%Y-%m-%d %H:%M")

    # Owner (Unix only; graceful on Windows)
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
        # Skip hidden dirs (e.g. .git)
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for fname in filenames:
            if stop_event.is_set():
                return
            fpath = os.path.join(dirpath, fname)
            yield ("file", fpath)


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
) -> Generator:
    """
    Scan root (local path or UNC) and yield JSON-serialisable event dicts.

    Architecture: one walk thread feeds a bounded file_queue; a ThreadPoolExecutor
    with `workers` threads analyses files in parallel; results flow through an
    events_queue back to this generator.

    Event types:
      {type: "log",      message: str}
      {type: "progress", scanned: int, hits: int, current: str}
      {type: "finding",  ...}
      {type: "summary",  scanned: int, hits: int, reportFile: str}
      {type: "error",    message: str}
    """
    _FILE_TIMEOUT = 30.0   # seconds before a slow file is skipped
    _FLUSH_EVERY_N = 500   # partial report flush: every N findings …
    _FLUSH_EVERY_SECS = 60.0  # … or every 60 seconds, whichever comes first

    is_smb = is_unc_path(root)

    yield {"type": "log", "message": f"Starting scan of: {root} (workers={workers})"}

    if is_smb and not SMB_AVAILABLE:
        yield {"type": "error", "message": "smbprotocol is not installed. Run: pip install smbprotocol"}
        return

    # ── Suppression setup ──────────────────────────────────────────────────────
    if is_smb:
        suppressions = load_suppressions(os.getcwd())
    else:
        if not os.path.exists(root):
            yield {"type": "error", "message": f"Path does not exist or is not accessible: {root}"}
            return
        suppressions = load_suppressions(root)

    # ── Report file paths (set up early so partial is written as findings arrive)
    if reports_dir is None:
        reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")

    os.makedirs(reports_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(reports_dir, f"LeakLens_{timestamp}.json")
    partial_file = os.path.join(reports_dir, f"LeakLens_{timestamp}.partial.json")

    # SMB share root used for relative paths and suppression checks
    if is_smb:
        _srv, _shr, _ = parse_unc(root)
        unc_share_root = f"\\\\{_srv}\\{_shr}"
    else:
        unc_share_root = ""

    # ── Shared mutable state — ALL mutations guarded by _lock ──────────────────
    _lock = threading.Lock()
    _state = {
        "file_count": 0,
        "hit_count": 0,
        "last_flush_count": 0,
        "last_flush_time": time.time(),
    }
    results: list = []

    def _flush_partial() -> None:
        """Atomically write a partial report snapshot to disk (no lock held on I/O)."""
        try:
            with _lock:
                snapshot = list(results)
                fc = _state["file_count"]
                hc = _state["hit_count"]
            tmp = partial_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as _f:
                json.dump({
                    "scanPath": root,
                    "scanDate": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "scanned": fc,
                    "hits": hc,
                    "partial": True,
                    "findings": snapshot,
                }, _f, indent=2)
            os.replace(tmp, partial_file)
        except OSError:
            pass

    # ── Queues ────────────────────────────────────────────────────────────────
    # file_q: walk → workers.  Bounded to keep memory under control.
    _file_q: queue.Queue = queue.Queue(maxsize=max(workers * 8, 64))
    # event_q: workers → main generator.
    _event_q: queue.Queue = queue.Queue()

    # ── Per-file analysis (called from worker threads, no lock held) ───────────
    def _analyse_item(item: tuple) -> tuple:
        """
        Analyse a single file item (local or SMB).
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
        ext = os.path.splitext(fname)[1].lower()
        name_base = os.path.splitext(fname.lower())[0]
        binary_risk = ext in FLAGGED_EXTENSIONS
        risky_name = (
            fname.lower() in FLAGGED_EXACT_NAMES
            or any(n in name_base for n in FLAGGED_NAMES)
        )
        size_bytes = stat.st_size if hasattr(stat, "st_size") else 0
        matched = []

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
            "smbShare": unc_share_root,
            "smbServer": _srv,
            "smbRelativePath": rel_path,
        }

        finding = build_finding(
            path=smb_path,
            ext=ext,
            size_bytes=size_bytes,
            last_modified=last_modified,
            last_accessed=last_accessed,
            owner="",
            matched_patterns=matched,
            risky_name=risky_name,
            binary_risk=binary_risk,
            smb_meta=smb_meta,
        )

        if finding is None:
            return None, smb_path

        pids = [f["id"] for f in finding.get("findingsDetail", [])]
        if is_suppressed(smb_path, pids, suppressions, unc_share_root):
            return None, smb_path

        return finding, smb_path

    # ── Walk thread: feeds _file_q ─────────────────────────────────────────────
    def _walk() -> None:
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
                    _file_q.put(ev)   # blocks if queue full (natural backpressure)
            else:
                for ev in _scan_local(root, max_size, stop_event):
                    if stop_event.is_set():
                        break
                    _file_q.put(ev)
        finally:
            # Poison pill: one per worker so each exits its get() loop
            for _ in range(workers):
                _file_q.put(None)

    # ── Worker: consumes _file_q, puts events into _event_q ───────────────────
    def _worker() -> None:
        while not stop_event.is_set():
            try:
                item = _file_q.get(timeout=1.0)
            except queue.Empty:
                continue

            if item is None:
                break   # poison pill received

            fpath = item[1] if len(item) > 1 else "?"
            finding = None

            # Submit analysis with a per-file timeout so one slow file can't
            # stall a worker indefinitely (SMB connection_timeout=30 handles
            # most hangs, but this is an additional safety net).
            with ThreadPoolExecutor(max_workers=1) as _inner:
                fut = _inner.submit(_analyse_item, item)
                done_futs, _ = fut_wait([fut], timeout=_FILE_TIMEOUT)

            if not done_futs:
                _event_q.put({
                    "type": "log",
                    "message": f"[TIMEOUT] Skipped slow file (>{_FILE_TIMEOUT:.0f}s): {fpath}",
                })
            else:
                try:
                    finding, fpath = fut.result()
                except Exception as e:
                    _event_q.put({"type": "log", "message": f"[ERROR] {fpath}: {e}"})

            # Always increment file_count exactly once per file
            need_flush = False
            with _lock:
                _state["file_count"] += 1
                fc = _state["file_count"]
                if finding is not None:
                    _state["hit_count"] += 1
                    hc = _state["hit_count"]
                    results.append(finding)
                    # Optimistically claim the flush slot to prevent double-flush
                    if (hc - _state["last_flush_count"] >= _FLUSH_EVERY_N or
                            time.time() - _state["last_flush_time"] >= _FLUSH_EVERY_SECS):
                        need_flush = True
                        _state["last_flush_count"] = hc
                        _state["last_flush_time"] = time.time()
                else:
                    hc = _state["hit_count"]

            if finding is not None:
                _event_q.put(finding)
            if fc % 100 == 0 or fc == 1:
                _event_q.put({
                    "type": "progress",
                    "scanned": fc,
                    "hits": hc,
                    "current": fpath,
                })
            if need_flush:
                _flush_partial()

        _event_q.put(("__done__",))   # signal this worker has finished

    # ── Orchestrate: start walk + worker pool, consume events ─────────────────
    walk_thread = threading.Thread(target=_walk, daemon=True)
    walk_thread.start()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        for _ in range(workers):
            executor.submit(_worker)

        # Drain events_queue until all workers signal done
        done_workers = 0
        fatal_error = False
        while done_workers < workers:
            item = _event_q.get()
            if isinstance(item, tuple) and item == ("__done__",):
                done_workers += 1
                continue
            if not isinstance(item, dict):
                continue
            yield item
            if item.get("type") == "error":
                fatal_error = True
                stop_event.set()

    walk_thread.join(timeout=5)

    if fatal_error:
        return

    with _lock:
        fc = _state["file_count"]
        hc = _state["hit_count"]

    # Final progress tick
    yield {"type": "progress", "scanned": fc, "hits": hc, "current": ""}

    # ── Save final JSON report ────────────────────────────────────────────────
    report = {
        "scanPath": root,
        "scanDate": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scanned": fc,
        "hits": hc,
        "findings": results,
    }

    try:
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        try:
            os.remove(partial_file)
        except OSError:
            pass
        yield {"type": "log", "message": f"Report saved: {report_file}"}
    except OSError as e:
        yield {"type": "log", "message": f"Could not save report: {e}"}
        report_file = ""

    yield {"type": "summary", "scanned": fc, "hits": hc, "reportFile": report_file}
