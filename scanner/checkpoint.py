"""
LeakLens checkpoint — resume support helpers.
"""
import hashlib
import json
import os


# ─── Checkpoint helpers ───────────────────────────────────────────────────────

def _ckpt_path(root: str, reports_dir: str) -> str:
    """Return the checkpoint file path for a given scan root."""
    root_hash = hashlib.sha256(root.encode("utf-8", "replace")).hexdigest()[:16]
    return os.path.join(reports_dir, f"checkpoint_{root_hash}.json")


def _load_ckpt(ckpt_file: str) -> tuple:
    """
    Load a checkpoint file.
    Returns (last_path: str | None, scanned_count: int, db_file: str | None, scan_id: str | None).
    """
    try:
        with open(ckpt_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return (
            data.get("last_path"),
            int(data.get("scanned", 0)),
            data.get("db_file") or None,
            data.get("scan_id") or None,
        )
    except (OSError, json.JSONDecodeError, ValueError):
        return None, 0, None, None


def _save_ckpt(ckpt_file: str, last_path: str, scanned: int,
               db_file: str = "", scan_id: str = "") -> None:
    """Write a checkpoint file atomically."""
    try:
        tmp = ckpt_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({
                "last_path": last_path,
                "scanned":   scanned,
                "db_file":   db_file,
                "scan_id":   scan_id,
            }, f)
        os.replace(tmp, ckpt_file)
    except OSError:
        pass
