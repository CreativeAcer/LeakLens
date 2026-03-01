"""
LeakLens checkpoint — resume support helpers.
"""
import hashlib
import json
import os


# ─── Checkpoint helpers ───────────────────────────────────────────────────────

def _ckpt_path(root: str, reports_dir: str) -> str:
    """Return the checkpoint file path for a given scan root."""
    root_hash = hashlib.md5(root.encode("utf-8", "replace")).hexdigest()[:12]
    return os.path.join(reports_dir, f"checkpoint_{root_hash}.json")


def _load_ckpt(ckpt_file: str) -> tuple:
    """
    Load a checkpoint file.
    Returns (last_path: str | None, scanned_count: int).
    """
    try:
        with open(ckpt_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("last_path"), int(data.get("scanned", 0))
    except (OSError, json.JSONDecodeError, ValueError):
        return None, 0


def _save_ckpt(ckpt_file: str, last_path: str, scanned: int) -> None:
    """Write a checkpoint file atomically."""
    try:
        tmp = ckpt_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"last_path": last_path, "scanned": scanned}, f)
        os.replace(tmp, ckpt_file)
    except OSError:
        pass
