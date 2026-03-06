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
      2. net view          — Windows built-in, no install needed, uses current session auth
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

    # 2. net view (Windows built-in, no install required)
    #    Only usable when no explicit credentials are provided — net view uses the
    #    current Windows session and silently ignores any username/password passed to it.
    if on_windows and not username and shutil.which("net"):
        return _list_shares_netview(host)

    # 3. smbclient binary (Linux/macOS, supports explicit credentials)
    if shutil.which("smbclient"):
        return _list_shares_binary(host, username, password, domain, port)

    # Credentials were supplied but no method that honours them is available.
    if on_windows and username:
        raise RuntimeError(
            "Credential-based share enumeration on Windows requires impacket.\n"
            "Install it with: pip install impacket --prefer-binary\n"
            "Or leave Username blank to enumerate using your current Windows session."
        )

    raise RuntimeError(
        "Share enumeration is unavailable. Options:\n"
        "  Windows : pip install impacket --prefer-binary\n"
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
