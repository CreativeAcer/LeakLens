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
import threading
from typing import Generator

from scanner.patterns import (
    CONTENT_PATTERNS,
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
    matchLine, matchSnippet).
    Applies confidence adjustments for docs paths and placeholder values.
    """
    in_docs = is_docs_path(path)
    lines = content.split('\n')
    matched = []

    for pattern in CONTENT_PATTERNS:
        try:
            m = re.search(pattern["regex"], content)
        except re.error:
            continue
        if not m:
            continue

        # Global post-match placeholder filter — skips obvious dummy values
        # that inline lookaheads in individual patterns may not cover
        if is_placeholder_match(m.group(0)):
            continue

        conf = pattern["confidence"]

        # Reduce confidence for docs/examples directories
        if in_docs:
            conf = max(1, conf - 3)

        # Extract match location and the full line it appeared on
        line_num = content[:m.start()].count('\n') + 1
        raw_line = lines[line_num - 1].strip() if line_num <= len(lines) else m.group(0)
        snippet = raw_line[:120] + ('…' if len(raw_line) > 120 else '')

        matched.append({
            "id": pattern["id"],
            "name": pattern["name"],
            "confidence": conf,
            "risk": get_risk_level(conf),
            "matchLine": line_num,
            "matchSnippet": snippet,
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
    """Walk a local directory and yield findings."""
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
    """Walk an SMB share and yield findings."""
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

    for smb_path, fname, stat in walk_smb(unc_root, stop_event=stop_event):
        if stop_event.is_set():
            return
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
) -> Generator:
    """
    Scan root (local path or UNC) and yield JSON-serialisable event dicts.

    Event types:
      {type: "log",      message: str}
      {type: "progress", scanned: int, hits: int, current: str}
      {type: "finding",  ...}
      {type: "summary",  scanned: int, hits: int, reportFile: str}
      {type: "error",    message: str}
    """
    is_smb = is_unc_path(root)

    yield {"type": "log", "message": f"Starting scan of: {root}"}

    if is_smb and not SMB_AVAILABLE:
        yield {"type": "error", "message": "smbprotocol is not installed. Run: pip install smbprotocol"}
        return

    # Determine local root for suppression file lookup
    if is_smb:
        # Load suppressions from current working directory for UNC scans
        suppressions = load_suppressions(os.getcwd())
    else:
        if not os.path.exists(root):
            yield {"type": "error", "message": f"Path does not exist or is not accessible: {root}"}
            return
        suppressions = load_suppressions(root)

    file_count = 0
    hit_count = 0
    results = []

    # ── SMB scan ──────────────────────────────────────────────────────────────
    if is_smb:
        server, share, _ = parse_unc(root)
        unc_share_root = f"\\\\{server}\\{share}"

        for event in _scan_smb(root, max_size, stop_event, username, password, domain):
            if stop_event.is_set():
                break

            if event[0] == "error":
                yield {"type": "error", "message": event[1]}
                return

            _, smb_path, fname, stat, srv, shr = event
            file_count += 1

            if file_count % 10 == 0 or file_count == 1:
                yield {"type": "progress", "scanned": file_count, "hits": hit_count, "current": smb_path}

            ext = os.path.splitext(fname)[1].lower()
            name_base = os.path.splitext(fname.lower())[0]

            binary_risk = ext in FLAGGED_EXTENSIONS
            risky_name = (
                fname.lower() in FLAGGED_EXACT_NAMES
                or any(n in name_base for n in FLAGGED_NAMES)
            )

            matched = []
            size_bytes = stat.st_size if hasattr(stat, "st_size") else 0

            if binary_risk:
                pass
            elif ext in TARGET_EXTENSIONS or (risky_name and ext == ""):
                if size_bytes <= max_size:
                    content = read_smb_file(smb_path, max_size)
                    if content:
                        matched = scan_content(content, smb_path)
            elif not risky_name:
                continue

            if not binary_risk and not risky_name and not matched:
                continue

            # Build timestamps from SMB stat
            try:
                last_modified = datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
                last_accessed = datetime.datetime.fromtimestamp(stat.st_atime).strftime("%Y-%m-%d %H:%M")
            except Exception:
                last_modified = ""
                last_accessed = ""

            # Relative path within the share
            try:
                rel_path = smb_path[len(unc_share_root):].lstrip("\\")
            except Exception:
                rel_path = smb_path

            smb_meta = {
                "smbShare": unc_share_root,
                "smbServer": srv,
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
                continue

            pids = [f["id"] for f in finding.get("findingsDetail", [])]
            if is_suppressed(smb_path, pids, suppressions, unc_share_root):
                continue

            hit_count += 1
            results.append(finding)
            yield finding

    # ── Local scan ────────────────────────────────────────────────────────────
    else:
        for event in _scan_local(root, max_size, stop_event):
            if stop_event.is_set():
                break

            _, fpath = event
            file_count += 1

            if file_count % 10 == 0 or file_count == 1:
                yield {"type": "progress", "scanned": file_count, "hits": hit_count, "current": fpath}

            finding = _check_local_file(fpath, max_size)
            if finding is None:
                continue

            pids = [f["id"] for f in finding.get("findingsDetail", [])]
            if is_suppressed(fpath, pids, suppressions, root):
                continue

            hit_count += 1
            results.append(finding)
            yield finding

    # Final progress tick
    yield {"type": "progress", "scanned": file_count, "hits": hit_count, "current": ""}

    # ── Save JSON report ──────────────────────────────────────────────────────
    if reports_dir is None:
        reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")

    os.makedirs(reports_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(reports_dir, f"LeakLens_{timestamp}.json")

    report = {
        "scanPath": root,
        "scanDate": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scanned": file_count,
        "hits": hit_count,
        "findings": results,
    }

    try:
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        yield {"type": "log", "message": f"Report saved: {report_file}"}
    except OSError as e:
        yield {"type": "log", "message": f"Could not save report: {e}"}
        report_file = ""

    yield {"type": "summary", "scanned": file_count, "hits": hit_count, "reportFile": report_file}
