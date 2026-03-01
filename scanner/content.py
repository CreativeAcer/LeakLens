"""
LeakLens content analysis — detection helpers and finding assembly.
"""
import os
import re
import pathlib

from scanner.patterns import (
    COMPILED_PATTERNS,
    PLACEHOLDER_VALUES,
    DOCS_DIRS,
    HASH_PATTERN_IDS,
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
