# LeakLens — Usage Guide

This guide covers installation, scanning, automated testing, and running the test server against intentionally dirty files. For a feature overview and API reference see [README.md](README.md).

---

## Contents

1. [Installation](#1-installation)
2. [Scanning via the UI](#2-scanning-via-the-ui)
3. [Running the automated tests](#3-running-the-automated-tests)
4. [Running the test server with dirty files](#4-running-the-test-server-with-dirty-files)
5. [Suppression — .leaklensignore](#5-suppression--leaklensignore)

---

## 1. Installation

```bash
# Clone the repository
git clone https://github.com/CreativeAcer/LeakLens.git
cd LeakLens

# (Recommended) create an isolated virtual environment
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# Install runtime dependencies
pip install -r requirements.txt

# Start the server
python leaklens.py
```

Opens at **http://localhost:3000**.

### Configuration

The server binds to `127.0.0.1:3000` by default. Override with environment variables:

```bash
LEAKLENS_PORT=8080 python leaklens.py
LEAKLENS_HOST=0.0.0.0 LEAKLENS_PORT=8080 python leaklens.py
```

> **Note:** Binding to `0.0.0.0` exposes the server on all network interfaces. Only do this on trusted networks — LeakLens has no authentication.

---

## 2. Scanning via the UI

### Local path scan

1. Open **http://localhost:3000**
2. Enter a local path in the **Scan Path** field — e.g. `/home/user/shares` or `C:\FileShares`
3. Adjust **Max File Size** (default 10 MB) — files larger than this are skipped
4. Set **Worker Threads** (1–16, default 8) — higher values speed up I/O-bound SMB scans
5. Click **Start Scan**

Findings stream in as they are detected. The progress bar shows files/second throughput.

### SMB / UNC path scan

1. Enter a UNC path — e.g. `\\fileserver\IT` or `\\192.168.1.10\data`
2. The **SMB Credentials** panel expands automatically
   - Leave blank to attempt guest/anonymous access
   - Enter `Domain\Username` + password for authenticated access
3. Use **Discover Shares** to enumerate all visible shares on the server before picking one
4. Click **Start Scan**

### Working with findings

- **Click any row** to open the detail drawer — shows the exact matched line and line number, file metadata (size, last modified, last accessed, owner), and remediation advice
- **Risk filter** (HIGH / MEDIUM / LOW / ALL) — narrow the table to the severity you care about
- **Search bar** — substring filter on filename or full path
- **Resume** checkbox — re-scanning the same path will skip already-processed files and continue from the last checkpoint

### Reports tab

Every completed scan is saved as a timestamped SQLite database in `reports/`. The **Reports** tab lists all saved scans — click any entry to reload its findings into the main view with full filtering, search, and the detail drawer.

---

## 3. Running the automated tests

### Setup

```bash
# Install pytest (only needed once)
pip install -r requirements-dev.txt
```

### Run all tests

```bash
python -m pytest tests/ -v
```

Expected output:

```
tests/test_api.py::test_index_returns_html PASSED
tests/test_api.py::test_status_not_scanning PASSED
...
tests/test_engine.py::test_scan_content_detects_aws_key PASSED
...
tests/test_patterns.py::test_plaintext_password[...] PASSED
...
======================== 149 passed in 0.2s ==============================
```

### Run a single module

```bash
python -m pytest tests/test_patterns.py -v   # pattern regex tests
python -m pytest tests/test_engine.py -v     # engine + content helpers
python -m pytest tests/test_api.py -v        # Flask endpoint tests
```

### What each module covers

| Module | What it tests |
|--------|---------------|
| `test_patterns.py` | Every pattern has at least one positive and one negative string. Structural checks: all patterns compile, `risk` field is consistent with `confidence`, no missing keys. |
| `test_engine.py` | `scan_content()` detects known patterns and respects confidence reduction in docs paths. `build_finding()` assembles correct finding dicts. `is_placeholder_match()` and `is_docs_path()` behave correctly. `load_suppressions()` and `is_suppressed()` handle global and per-pattern rules. |
| `test_api.py` | All Flask endpoints return correct status codes for happy paths and error cases. Path traversal in `GET /api/reports/<name>` is blocked. `scan_id` injection is rejected. Input validation rejects invalid hosts, page types, and missing required params. |

---

## 4. Running the test server with dirty files

The `testserver/` directory contains a Docker/Podman Samba image pre-loaded with 8 intentionally unsafe files. Use it to verify that LeakLens finds what it should — without touching real infrastructure.

### Prerequisites

Docker or Podman. The start scripts detect whichever is available. No Docker Compose needed.

### 4.1 — Start the container

```bash
# Linux / macOS
chmod +x testserver/start-testserver.sh
./testserver/start-testserver.sh

# Windows
testserver\start-testserver.bat
```

The container starts a Samba server on **port 4445** (non-standard to avoid conflict with the Windows SMB service on port 445). The share is read-only and requires no credentials.

You should see:

```
  [OK] Using docker
  [*] Building test server image...
  [OK] Image built
  [*] Starting test file server...
  Test server running on port 4445!
```

### 4.2 — Mount the share

LeakLens connects to SMB on port 445 by default, so you need to mount the share at a local path first, then scan that path.

**Linux:**

```bash
sudo mkdir -p /mnt/testshare
sudo mount -t cifs //127.0.0.1/testshare /mnt/testshare \
  -o port=4445,guest,vers=2.0
```

If `cifs-utils` is not installed:
```bash
sudo apt install cifs-utils    # Debian/Ubuntu
sudo dnf install cifs-utils    # Fedora/RHEL
```

**macOS:**

```
Finder → Go → Connect to Server → smb://127.0.0.1:4445/testshare
```
Or from Terminal:
```bash
open 'smb://127.0.0.1:4445/testshare'
```
The share mounts under `/Volumes/testshare` (Finder shows it in the sidebar).

**Windows:**

```cmd
net use Z: \\127.0.0.1\testshare "" /user:guest /port:4445
```

### 4.3 — Scan it

Open LeakLens at **http://localhost:3000**, enter the local mount path, leave credentials blank, and click **Start Scan**.

| Platform | Scan path |
|----------|-----------|
| Linux | `/mnt/testshare` |
| macOS | `/Volumes/testshare` |
| Windows | `Z:\` |

### 4.4 — Expected findings

All credentials in the test files are completely fake and exist only to trigger detection.

| File | Expected patterns |
|------|------------------|
| `deploy.ps1` | Plaintext Password, Connection String, PowerShell SecureString, Hardcoded PSCredential |
| `app.config` | Plaintext Password, Generic API Key/Token, Bearer Token |
| `passwords.txt` | NTLM Hash, Plaintext Password |
| `.env` | Plaintext Password, AWS Access Key, Base64 Credential, Stripe API Key |
| `nightly-backup.bat` | Net Use Credential |
| `db_maintenance.py` | Plaintext Password, Bearer Token |
| `id_rsa` | Private Key Header, Risky Filename (flagged by name) |
| `project-notes.md` | *(clean — no findings expected)* |

All 7 files with findings should appear in LeakLens. `project-notes.md` should produce no finding row.

### 4.5 — Stop the container

```bash
./testserver/stop-testserver.sh    # Linux / macOS
testserver\stop-testserver.bat     # Windows
```

Unmount the share on Linux before stopping (or after):

```bash
sudo umount /mnt/testshare
```

The container is stateless — stopping removes all state. Restart it any time with the start script.

---

## 5. Suppression — .leaklensignore

Drop a `.leaklensignore` file in your **scan root directory** to silence known-safe paths. The format mirrors `.gitignore` with an optional `[pattern_id]` section syntax for per-pattern rules.

```
# Suppress all findings under these paths (global rules)
archive/**
legacy/**
*.example.config

# Suppress only the md5_hash pattern in checksum files
[md5_hash]
checksums/**
*.md5

# Suppress aws_access_key matches in documentation
[aws_access_key]
docs/**
```

### Pattern ID reference

Use these IDs in `[pattern_id]` section headers:

| ID | Display name |
|----|-------------|
| `plaintext_password` | Plaintext Password |
| `connection_string` | Connection String |
| `ntlm_hash` | NTLM Hash |
| `md5_hash` | MD5 Hash |
| `sha1_hash` | SHA1 Hash |
| `sha256_hash` | SHA256 Hash |
| `sha512_hash` | SHA512 Hash |
| `bcrypt_hash` | Bcrypt Hash |
| `base64_credential` | Base64 Credential |
| `aws_access_key` | AWS Access Key |
| `generic_api_key` | Generic API Key/Token |
| `bearer_token_value` | Bearer Token |
| `private_key_header` | Private Key Header |
| `net_use_credential` | Net Use Credential |
| `ps_secure_string` | PowerShell SecureString |
| `hardcoded_pscredential` | Hardcoded PSCredential |
| `sql_sa_password` | SQL sa Password |
| `github_pat` | GitHub Personal Access Token |
| `gitlab_pat` | GitLab Personal Access Token |
| `azure_client_secret` | Azure Client Secret |
| `azure_storage_key` | Azure Storage Account Key |
| `dpapi_blob` | DPAPI Encrypted Blob |
| `stripe_key` | Stripe API Key |
| `slack_token` | Slack Token |
| `sendgrid_key` | SendGrid API Key |

The full list is also in `scanner/patterns.py` — each entry has an `"id"` field.
