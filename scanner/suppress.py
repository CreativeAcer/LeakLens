"""
LeakLens suppression — .leaklensignore parser and path matcher.
"""
import os
import fnmatch


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
