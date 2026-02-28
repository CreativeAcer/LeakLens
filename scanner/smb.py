"""
SMB/UNC path helpers for LeakLens.
Requires: smbprotocol (pip install smbprotocol)
"""

import re

try:
    import smbclient
    import smbclient.path
    SMB_AVAILABLE = True
except ImportError:
    SMB_AVAILABLE = False


def is_unc_path(path: str) -> bool:
    r"""Return True if path is a UNC path (\\server\share or //server/share)."""
    return path.startswith("\\\\") or path.startswith("//")


def normalize_unc(path: str) -> str:
    """Normalize UNC path to use backslashes."""
    return path.replace("/", "\\")


def parse_unc(path: str) -> tuple[str, str, str]:
    """
    Parse a UNC path into (server, share, relative_path).
    e.g. \\\\server\\share\\IT\\scripts -> ('server', 'share', 'IT\\\\scripts')
    """
    norm = normalize_unc(path).lstrip("\\")
    parts = norm.split("\\", 2)
    server = parts[0] if len(parts) > 0 else ""
    share = parts[1] if len(parts) > 1 else ""
    rel = parts[2] if len(parts) > 2 else ""
    return server, share, rel


def register_session(server: str, username: str = None, password: str = None, domain: str = None):
    """Register an SMB session for the given server."""
    if not SMB_AVAILABLE:
        raise RuntimeError("smbprotocol is not installed. Run: pip install smbprotocol")

    kwargs = {}
    if username:
        kwargs["username"] = username
    if password is not None:
        kwargs["password"] = password
    if domain:
        kwargs["auth_protocol"] = "ntlm"

    smbclient.register_session(server, **kwargs)


def list_shares(host: str, username: str = None, password: str = None, domain: str = None) -> list[str]:
    """List visible shares on the given SMB host."""
    if not SMB_AVAILABLE:
        raise RuntimeError("smbprotocol is not installed. Run: pip install smbprotocol")

    register_session(host, username=username, password=password, domain=domain)
    shares = smbclient.listshares(host)
    return list(shares)


def walk_smb(unc_root: str, stop_event=None):
    """
    Recursively walk an SMB share.
    Yields (smb_path, entry_name, smb_stat) for each file.
    smb_stat has .st_size, .st_mtime, .st_atime, .st_ctime attributes.
    """
    if not SMB_AVAILABLE:
        raise RuntimeError("smbprotocol is not installed. Run: pip install smbprotocol")

    def _recurse(path):
        if stop_event and stop_event.is_set():
            return
        try:
            for entry in smbclient.scandir(path):
                if stop_event and stop_event.is_set():
                    return
                full = f"{path}\\{entry.name}"
                if entry.is_dir(follow_symlinks=False):
                    yield from _recurse(full)
                elif entry.is_file(follow_symlinks=False):
                    try:
                        stat = entry.stat()
                        yield full, entry.name, stat
                    except Exception:
                        pass
        except Exception:
            pass

    yield from _recurse(normalize_unc(unc_root))


def read_smb_file(smb_path: str, max_size: int) -> str | None:
    """Read the content of a file over SMB. Returns None on error or if too large."""
    if not SMB_AVAILABLE:
        return None
    try:
        with smbclient.open_file(smb_path, mode="rb") as f:
            # Check size first
            f.seek(0, 2)
            size = f.tell()
            if size > max_size:
                return None
            f.seek(0)
            raw = f.read(max_size)
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        return None


def smb_file_size(smb_path: str) -> int:
    """Return file size in bytes for an SMB file, or 0 on error."""
    if not SMB_AVAILABLE:
        return 0
    try:
        stat = smbclient.stat(smb_path)
        return stat.st_size
    except Exception:
        return 0
