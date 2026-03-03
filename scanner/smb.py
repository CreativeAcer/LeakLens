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


def register_session(server: str, username: str = None, password: str = None,
                     domain: str = None, port: int = 445):
    """Register an SMB session for the given server."""
    if not SMB_AVAILABLE:
        raise RuntimeError("smbprotocol is not installed. Run: pip install smbprotocol")

    if username:
        kwargs = {
            "connection_timeout": 30,
            "port": port,
            "username": username,
        }
        if password is not None:
            kwargs["password"] = password
        if domain:
            kwargs["auth_protocol"] = "ntlm"
            kwargs["domain"] = domain
    else:
        # Null/anonymous session: use NTLM with a dummy username so that
        # Samba's "map to guest = Bad User" maps it to the guest account.
        # require_signing must be False because guest sessions have no signing key.
        smbclient.ClientConfig(require_secure_negotiate=False)
        kwargs = {
            "connection_timeout": 30,
            "port": port,
            "username": "nobody",
            "password": password if password is not None else "",
            "auth_protocol": "ntlm",
            "require_signing": False,
        }

    smbclient.register_session(server, **kwargs)


def list_shares(host: str, username: str = None, password: str = None,
                domain: str = None, port: int = 445) -> list[str]:
    """
    List visible shares on the given SMB host using the system smbclient binary.
    smbprotocol does not expose a share-enumeration API, so we shell out to
    the Samba smbclient tool which handles null sessions reliably.
    """
    import subprocess
    import shutil

    if not shutil.which("smbclient"):
        raise RuntimeError(
            "smbclient binary not found. Install samba-client (e.g. apt install smbclient)."
        )

    cmd = ["smbclient", "-L", f"//{host}", "-p", str(port)]

    if username:
        cred = username
        if password is not None:
            cred += f"%{password}"
        cmd.extend(["-U", cred])
        if domain:
            cmd.extend(["-W", domain])
    else:
        cmd.extend(["-N", "-U", "%"])  # null / anonymous session

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Connection to host timed out.")

    output = result.stdout + result.stderr

    shares = []
    in_list = False
    for line in output.splitlines():
        if "Sharename" in line and "Type" in line:
            in_list = True
            continue
        if not in_list:
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("-"):
            continue
        # Lines past the share list (workgroup section, reconnect notice, etc.)
        if not line.startswith("\t") and not line.startswith(" "):
            break
        parts = stripped.split()
        if parts:
            shares.append(parts[0])

    if not shares and result.returncode != 0:
        # Surface the actual smbclient error message
        msg = output.strip().splitlines()[-1] if output.strip() else "Unknown error"
        raise RuntimeError(msg)

    return shares


def walk_smb(unc_root: str, stop_event=None, port: int = 445):
    """
    Recursively walk an SMB share.
    Yields (smb_path, entry_name, smb_stat) for each file,
    or ("__error__", path, message) when a path is inaccessible.
    smb_stat has .st_size, .st_mtime, .st_atime, .st_ctime attributes.
    """
    if not SMB_AVAILABLE:
        raise RuntimeError("smbprotocol is not installed. Run: pip install smbprotocol")

    def _recurse(path):
        if stop_event and stop_event.is_set():
            return
        try:
            for entry in smbclient.scandir(path, port=port):
                if stop_event and stop_event.is_set():
                    return
                full = f"{path}\\{entry.name}"
                if entry.is_dir(follow_symlinks=False):
                    yield from _recurse(full)
                elif entry.is_file(follow_symlinks=False):
                    try:
                        # entry.stat() lazily fetches on default port 445;
                        # use smbclient.stat() with the explicit port instead.
                        stat = smbclient.stat(full, port=port)
                        yield full, entry.name, stat
                    except Exception as e:
                        yield ("__error__", full, str(e))
        except Exception as e:
            yield ("__error__", path, str(e))

    yield from _recurse(normalize_unc(unc_root))


def read_smb_file(smb_path: str, max_size: int, port: int = 445) -> str | None:
    """Read the content of a file over SMB. Returns None on error or if too large."""
    if not SMB_AVAILABLE:
        return None
    try:
        with smbclient.open_file(smb_path, mode="rb", port=port) as f:
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
