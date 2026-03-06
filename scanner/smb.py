"""
SMB/UNC path helpers for LeakLens.
Requires: smbprotocol (pip install smbprotocol)
"""

import os
import re
import threading
import time

try:
    import smbclient
    import smbclient.path
    SMB_AVAILABLE = True
except ImportError:
    SMB_AVAILABLE = False


# ─── SMB concurrency limiter ──────────────────────────────────────────────────
#
# SMB2 uses a credit-based flow-control system. Each request (open, read, stat,
# close) costs 1 credit; the server replenishes credits in responses. When many
# worker threads fire simultaneous requests against the same connection the pool
# can hit 0, which causes subsequent requests — including GC-triggered Close
# requests from finalised directory handles — to raise:
#   SMBException: Request requires 1 credits but only 0 credits are available
#
# _SMB_SEM caps the total number of in-flight SMB I/O operations across the
# walk thread and all worker threads. A value of 4 is conservative enough to
# prevent exhaustion against both Samba and Windows servers without significantly
# reducing throughput (directory listings are cheap; file reads are the bottleneck).

_SMB_SEM = threading.Semaphore(4)

# Delays (seconds) between successive retries on credit exhaustion.
_CREDIT_DELAYS = (0.05, 0.15, 0.4, 1.0, 2.5)


def _is_credit_error(exc: Exception) -> bool:
    return "credits" in str(exc).lower()


def _smb_retry(fn, *args, **kwargs):
    """
    Call fn(*args, **kwargs), retrying with backoff on SMB credit-exhaustion.
    All other exceptions are re-raised immediately.
    After all retries are exhausted the final attempt's exception propagates.
    """
    for delay in _CREDIT_DELAYS:
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            if _is_credit_error(e):
                time.sleep(delay)
            else:
                raise
    return fn(*args, **kwargs)  # final attempt — let any exception propagate


# ─── Path utilities ───────────────────────────────────────────────────────────

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


# ─── Session management ───────────────────────────────────────────────────────

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


# ─── Share enumeration ────────────────────────────────────────────────────────

def list_shares(host: str, username: str = None, password: str = None,
                domain: str = None, port: int = 445) -> list[str]:
    """
    List visible shares on the given SMB host.

    Tries in order:
      1. impacket          — pure Python, cross-platform, supports explicit credentials
      2. net use + net view — Windows built-in (no install), supports explicit credentials
      3. smbclient binary  — Linux/macOS (apt install smbclient / brew install samba)

    Raises RuntimeError if no method is available or enumeration fails.
    """
    import shutil
    import platform
    on_windows = platform.system() == "Windows"

    # 1. impacket (all platforms, supports explicit credentials)
    try:
        return _list_shares_impacket(host, username, password, domain, port)
    except ImportError:
        pass

    # 2. net use + net view (Windows built-in, supports explicit credentials)
    if on_windows and shutil.which("net"):
        if username:
            return _list_shares_netview_with_creds(host, username, password, domain)
        return _list_shares_netview(host)

    # 3. smbclient binary (Linux/macOS, supports explicit credentials)
    if shutil.which("smbclient"):
        return _list_shares_binary(host, username, password, domain, port)

    raise RuntimeError(
        "Share enumeration is unavailable. Options:\n"
        "  Windows : Ensure 'net' is in PATH (built-in on all Windows versions)\n"
        "  Linux   : apt install smbclient\n"
        "  macOS   : brew install samba"
    )


def _list_shares_impacket(host: str, username: str = None, password: str = None,
                           domain: str = None, port: int = 445) -> list[str]:
    """Enumerate shares via impacket's NetrShareEnum DCE/RPC call."""
    from impacket.dcerpc.v5 import transport, srvsvc  # raises ImportError if absent

    rpctransport = transport.SMBTransport(
        host, port, r"\srvsvc",
        username=username or "",
        password=password or "",
        domain=domain or "",
    )
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(srvsvc.MSRPC_UUID_SRVSVC)
    resp = srvsvc.hNetrShareEnum(dce, 1)
    dce.disconnect()

    shares = []
    for share in resp["InfoStruct"]["ShareInfo"]["Level1"]["Buffer"]:
        name = share["shi1_netname"].rstrip("\x00")
        if name:
            shares.append(name)
    return shares


# ─── Win32 credential helpers (Windows only) ─────────────────────────────────

def _wnet_connect(host: str, username: str, password: str | None,
                  domain: str | None) -> bool:
    """
    Connect to \\\\host\\IPC$ using the Win32 WNetAddConnection2 API.
    Credentials are passed through the API — not exposed on the command line.
    Returns True on success, False if the API is unavailable or the call fails.
    """
    try:
        import ctypes
        import ctypes.wintypes

        class NETRESOURCEW(ctypes.Structure):
            _fields_ = [
                ("dwScope",       ctypes.wintypes.DWORD),
                ("dwType",        ctypes.wintypes.DWORD),
                ("dwDisplayType", ctypes.wintypes.DWORD),
                ("dwUsage",       ctypes.wintypes.DWORD),
                ("lpLocalName",   ctypes.wintypes.LPWSTR),
                ("lpRemoteName",  ctypes.wintypes.LPWSTR),
                ("lpComment",     ctypes.wintypes.LPWSTR),
                ("lpProvider",    ctypes.wintypes.LPWSTR),
            ]

        nr = NETRESOURCEW()
        nr.dwType = 0  # RESOURCETYPE_ANY
        nr.lpRemoteName = f"\\\\{host}\\IPC$"

        user = f"{domain}\\{username}" if domain else username
        rc = ctypes.windll.mpr.WNetAddConnection2W(
            ctypes.byref(nr), password or "", user, 0
        )
        return rc == 0
    except (AttributeError, OSError):
        # ctypes.windll is not available on non-Windows, or mpr.dll is missing.
        return False


def _list_shares_netview_with_creds(host: str, username: str, password: str = None,
                                     domain: str = None) -> list[str]:
    """
    Enumerate shares on Windows using an authenticated session.

    Uses WNetAddConnection2 (Win32 API) to establish the IPC$ session so that
    credentials are passed through the API rather than appearing on the command
    line of 'net use'.  Falls back to 'net use' only if the Win32 call fails
    (e.g., on very old Windows versions where mpr.dll behaves differently).
    The IPC$ session is always cleaned up in a finally block.
    """
    import subprocess

    unc_ipc = f"\\\\{host}\\IPC$"
    user_arg = f"{domain}\\{username}" if domain else username

    wnet_ok = _wnet_connect(host, username, password, domain)

    if not wnet_ok:
        # Fall back: password appears on the 'net use' command line.
        # This is unavoidable without the Win32 API (mpr.dll WNetAddConnection2).
        auth_result = subprocess.run(
            ["net", "use", unc_ipc, password or "", f"/user:{user_arg}"],
            capture_output=True, timeout=15,
        )
        oem = "oem" if os.name == "nt" else "utf-8"
        auth_out = (auth_result.stdout + auth_result.stderr).decode(oem, errors="replace")
        if auth_result.returncode != 0:
            msg = auth_out.strip().splitlines()[-1] if auth_out.strip() else "Authentication failed"
            raise RuntimeError(f"Authentication failed: {msg}")

    try:
        return _list_shares_netview(host)
    finally:
        # Always clean up the IPC$ session, regardless of how it was established.
        subprocess.run(
            ["net", "use", unc_ipc, "/delete", "/yes"],
            capture_output=True, timeout=10,
        )


def _list_shares_netview(host: str) -> list[str]:
    """
    Enumerate shares using the Windows built-in 'net view' command.
    Uses the current Windows session credentials — no explicit cred support.
    Falls back automatically when impacket is not installed.
    """
    import subprocess

    try:
        result = subprocess.run(
            ["net", "view", f"\\\\{host}", "/all"],
            capture_output=True, timeout=15,
        )
        # net view outputs in the system OEM codepage (e.g. cp850), not UTF-8.
        # Decode with errors="replace" so non-ASCII share names don't crash.
        oem = "oem" if os.name == "nt" else "utf-8"
        result_stdout = result.stdout.decode(oem, errors="replace")
        result_stderr = result.stderr.decode(oem, errors="replace")
    except subprocess.TimeoutExpired:
        raise RuntimeError("Connection to host timed out.")

    output = result_stdout + result_stderr

    # net view output (English locale):
    #   Share name   Resource    Remark
    #   -----------------------------------------------
    #   NETLOGON                 Logon server share
    #   SYSVOL                   Logon server share
    #   The command completed successfully.
    shares = []
    in_list = False
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("-"):
            in_list = True
            continue
        if not in_list:
            continue
        if stripped.lower().startswith("the command"):
            break
        parts = stripped.split()
        if parts:
            shares.append(parts[0])

    if not shares and result.returncode != 0:
        msg = output.strip().splitlines()[-1] if output.strip() else "Unknown error"
        raise RuntimeError(f"net view failed: {msg}")

    return shares


def _list_shares_binary(host: str, username: str = None, password: str = None,
                         domain: str = None, port: int = 445) -> list[str]:
    """Enumerate shares by shelling out to the smbclient binary (Linux/macOS)."""
    import subprocess
    import tempfile

    cmd = ["smbclient", "-L", f"//{host}", "-p", str(port)]

    cred_path = None
    try:
        if username:
            # Write credentials to a temp file to avoid exposing them in process args.
            # On Linux, process command lines are visible to any user via /proc/PID/cmdline.
            fd, cred_path = tempfile.mkstemp(suffix=".cred")
            try:
                with os.fdopen(fd, "w") as cf:
                    cf.write(f"username = {username}\n")
                    cf.write(f"password = {password or ''}\n")
                    if domain:
                        cf.write(f"domain = {domain}\n")
                os.chmod(cred_path, 0o600)
            except OSError:
                try:
                    os.unlink(cred_path)
                except OSError:
                    pass
                cred_path = None
                raise
            cmd.extend(["-A", cred_path])
        else:
            cmd.extend(["-N", "-U", "%"])  # null / anonymous session

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Connection to host timed out.")

    finally:
        if cred_path:
            try:
                os.unlink(cred_path)
            except OSError:
                pass

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


# ─── Directory walk ───────────────────────────────────────────────────────────

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

        # Consume the entire scandir listing immediately under the semaphore so
        # the SMBDirectoryIO handle is closed before we yield anything to the
        # caller. Leaving the handle open inside a paused generator causes GC
        # finalizer errors ("0 credits") when concurrent worker threads have
        # exhausted the SMB credit pool.
        try:
            with _SMB_SEM:
                entries = _smb_retry(
                    lambda: list(smbclient.scandir(path, port=port))
                )
        except Exception as e:
            yield ("__error__", path, str(e))
            return

        for entry in entries:
            if stop_event and stop_event.is_set():
                return
            full = f"{path}\\{entry.name}"
            if entry.is_dir(follow_symlinks=False):
                yield from _recurse(full)
            elif entry.is_file(follow_symlinks=False):
                try:
                    with _SMB_SEM:
                        stat = _smb_retry(smbclient.stat, full, port=port)
                    yield full, entry.name, stat
                except Exception as e:
                    yield ("__error__", full, str(e))

    yield from _recurse(normalize_unc(unc_root))


# ─── File reading ─────────────────────────────────────────────────────────────

def read_smb_file(smb_path: str, max_size: int, port: int = 445) -> str | None:
    """Read the content of a file over SMB. Returns None on error or if too large."""
    if not SMB_AVAILABLE:
        return None
    for delay in (*_CREDIT_DELAYS, None):
        try:
            with _SMB_SEM:
                with smbclient.open_file(smb_path, mode="rb", port=port) as f:
                    f.seek(0, 2)
                    size = f.tell()
                    if size > max_size:
                        return None
                    f.seek(0)
                    raw = f.read(max_size)
            return raw.decode("utf-8", errors="ignore")
        except Exception as e:
            if delay is not None and _is_credit_error(e):
                time.sleep(delay)
                continue
            return None
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
