<p align="center">
  <b>LeakLens – Credential Exposure Scanner for File Shares</b>
</p>

<p align="center">
  <a href="https://github.com/CreativeAcer/LeakLens/stargazers">
    <img src="https://img.shields.io/github/stars/CreativeAcer/LeakLens?style=for-the-badge" />
  </a>
  <a href="https://github.com/CreativeAcer/LeakLens/forks">
    <img src="https://img.shields.io/github/forks/CreativeAcer/LeakLens?style=for-the-badge" />
  </a>
  <a href="https://github.com/CreativeAcer/LeakLens/issues">
    <img src="https://img.shields.io/github/issues/CreativeAcer/LeakLens?style=for-the-badge" />
  </a>
  <a href="https://github.com/CreativeAcer/LeakLens/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/CreativeAcer/LeakLens?style=for-the-badge" />
  </a>
  <a href="https://github.com/CreativeAcer/LeakLens/releases">
    <img src="https://img.shields.io/github/v/release/CreativeAcer/LeakLens?style=for-the-badge" />
  </a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black" />
  <img src="https://img.shields.io/badge/CSS-1572B6?style=for-the-badge&logo=css3&logoColor=white" />
  <img src="https://img.shields.io/badge/HTML-E34F26?style=for-the-badge&logo=html5&logoColor=white" />
  <img src="https://img.shields.io/badge/Shell-121011?style=for-the-badge&logo=gnu-bash&logoColor=white" />
  <img src="https://img.shields.io/badge/Batchfile-4D4D4D?style=for-the-badge&logo=windows&logoColor=white" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Open%20Source-❤-success?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Security-Credential_Scanner-critical?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Use%20Case-File_Share_Auditing-informational?style=for-the-badge" />
</p>

![LeakLens Banner](Images/leaklens-banner.svg)

<div align="center">

### 🔍 Catch exposed credentials on file shares before they become an incident

LeakLens scans SMB/UNC shares and local paths for passwords, keys, tokens, and secrets —  
with **confidence scoring**, **live browser streaming**, and **zero mounting required**.

**Built for pentesters • Blue teams • Security auditors • DFIR**

<a href="https://github.com/CreativeAcer/LeakLens">
  <img src="https://img.shields.io/badge/View%20on-GitHub-black?style=for-the-badge&logo=github" />
</a>
<a href="#quick-start">
  <img src="https://img.shields.io/badge/Get%20Started-Quick%20Start-success?style=for-the-badge" />
</a>

</div>

Tools like truffleHog and gitleaks excel at scanning Git repositories and CI artifacts.
LeakLens targets a different, often neglected attack surface: shared folders and internal file servers. It scans `\\server\share` directly, no mounting and streams confidence-scored findings to a browser in real time. 

Born from a pentest finding: a domain admin password sitting in a plaintext `.ps1` file on an open file share, readable by every user in the domain. LeakLens exists to find those before an attacker does.

### How LeakLens fits alongside other secret scanners

LeakLens complements tools like truffleHog and gitleaks by focusing on a different attack surface: file shares and internal paths.

| Tool       | Primary focus            | Native SMB/UNC scanning | Filesystem paths | Git history | Live UI streaming | Resume scans |
|------------|--------------------------|-------------------------|------------------|-------------|-------------------|--------------|
| LeakLens   | File shares, local paths | ✅ Yes                  | ✅ Yes           | ❌ No       | ✅ Yes            | ✅ Yes       |
| truffleHog | Git, CI, artifacts       | ❌ No (mount required)  | ⚠️ Yes           | ✅ Yes      | ❌ No             | ❌ No        |
| gitleaks   | Git repos & commits      | ❌ No                   | ❌ No            | ✅ Yes      | ❌ No             | ❌ No        |

LeakLens is not a replacement for repository secret scanners, it fills the gap where credentials leak into shared folders, scripts, and internal file servers.

---

## What it does

Scans Windows file shares (and local paths) for exposed credentials:

- Connects directly to SMB/UNC paths — no `net use`, no manual mount
- Enumerates shares on a server with one click
- Scans text files for passwords, hashes, keys, tokens, and connection strings
- Flags sensitive file types (`.pfx`, `.ppk`, `.kdbx`, `.pem`, ...) and risky filenames (`id_rsa`, `credentials`, `.env`, ...)
- Scores every finding 1–10 so you spend time on what matters
- Shows the **exact matched line and line number** for every content finding — no need to open the file
- Streams results to a browser UI in real time using Server-Sent Events
- Scans files in parallel using a configurable number of worker threads
- Saves findings to a **SQLite database** per scan for fast historical querying
- Can **resume interrupted scans** from a checkpoint without rescanning files already processed
- Saves a timestamped JSON report of every scan, browsable in the **Reports tab**

---

## Requirements

- Python 3.11+
- Dependencies (pinned):
  - `flask==3.1.3`
  - `smbprotocol==1.16.0`
  - `PyYAML==6.0.2`

---

## Quick Start

**Windows**
```
start.bat
```

**Linux / macOS**
```bash
chmod +x start.sh && ./start.sh
```

Or run directly:
```bash
python3 -m pip install -r requirements.txt
python3 leaklens.py
```

Opens at **http://localhost:3000**.

The server binds to `127.0.0.1:3000` by default.
Override with environment variables: `LEAKLENS_HOST` and `LEAKLENS_PORT`.

---

## Scanning a file share

1. Enter a UNC path — `\\server\share` — or a local path
2. For UNC paths the **SMB Credentials** panel appears automatically
   - Leave blank to try guest/anonymous access first
   - Or enter domain credentials for authenticated scans
3. Click **Discover Shares** to enumerate all visible shares on a server
4. Set the max file size to scan (default: 10 MB)
5. Set the number of **Worker Threads** (1–16, default 8) to control scan parallelism
6. Enable **Resume** to continue a previously interrupted scan from its checkpoint
7. Click **Start Scan**
8. Findings stream in as they are found — click any row to see the **matched line**, file metadata, and remediation advice
9. Open the **Reports** tab at any time to reload a previous scan

---

## What it detects

### Content patterns

| Pattern | Examples | Confidence |
|---|---|---|
| Plaintext Password | `password=`, `"password": "..."`, `DB_PASSWORD=` | 8/10 |
| Connection String | Embedded passwords in connection strings | 8/10 |
| NTLM / LM Hash | `lm_hash:ntlm_hash` pairs | 8/10 |
| Bcrypt Hash | `$2a$`, `$2b$`, `$2y$` | 8/10 |
| Base64 Credential | Base64 values next to credential keywords | 5/10 |
| AWS Access Key | `AKIA…` | 9/10 |
| GitHub / GitLab PAT | `ghp_…`, `gho_…`, `glpat-…` | 10/10 |
| Stripe API Key | `sk_live_…`, `sk_test_…` | 10/10 |
| Slack Token | `xoxb-…`, `xoxp-…` | 10/10 |
| SendGrid API Key | `SG.xxxx.xxxx` | 10/10 |
| Azure Client Secret / Storage Key | Azure credential formats | 8/10 |
| DPAPI Encrypted Blob | DPAPI blob headers (base64 or hex) | 8/10 |
| API Key / Bearer Token | Key assignments and `Bearer` tokens | 6/10 |
| Private Key Header | `-----BEGIN … PRIVATE KEY-----` | 10/10 |
| Net Use Credential | `net use /user:` commands | 8/10 |
| PowerShell SecureString | Hardcoded `ConvertTo-SecureString` literals | 8/10 |
| PowerShell PSCredential | Hardcoded `PSCredential` objects | 6/10 |
| SQL sa Password | `sa password =` | 8/10 |
| MD5 / SHA1 / SHA256 / SHA512 | Hash strings by length | 3–4/10 |

### File type flags (no content scan needed)
`.kdbx` `.kdb` `.pfx` `.p12` `.ppk` `.pem` `.key` `.jks` `.wallet`

### Filename flags
Files whose name contains: `password`, `creds`, `secret`, `token`, `id_rsa`, `apikey`, `.env`, and similar.

---

## Confidence scoring

Every finding gets a score from 1–10 based on how certain the match is:

| Score | Meaning |
|---|---|
| 9–10 | Near-certain — private key, AWS access key |
| 7–8 | High confidence — plaintext password, NTLM hash, connection string, SecureString |
| 5–6 | Moderate — API key pattern, PSCredential, suspicious filename |
| 3–4 | Low signal — hash strings that could be checksums rather than credentials |

Confidence is reduced automatically for files in `docs/`, `examples/`, `test/`, and similar directories. Files where only generic hash patterns match are downgraded to LOW with a note.

---

## False positive reduction

- Common placeholders (`changeme`, `example`, `${password}`, `***`, etc.) are excluded from password matches
- Docs and example directories reduce confidence by 3 points automatically
- Hash-only findings are demoted to LOW with the note: *"Hash strings detected — verify these are credential hashes and not integrity checksums."*
- Lockfiles (`package-lock.json`, `yarn.lock`, `poetry.lock`, etc.) are skipped entirely — they are dense with hash strings that would otherwise flood results

---

## Suppressing known noise (.leaklensignore)

Drop a `.leaklensignore` file in your scan root to silence known-safe paths. The format mirrors `.gitignore`:

```
# Suppress entire paths
archive/**
docs/**
*.example.config

# Suppress a specific pattern type in specific paths
[md5_hash]
checksums/**
*.md5
```

Pattern IDs are listed in `scanner/patterns.py`.

---

## Match evidence

Every content finding includes the exact line that triggered the match. The detail drawer shows each detected pattern alongside its line number and the full matched line, so you can confirm the finding without opening the file:

```
Plaintext Password    Line 4
  DB_PASSWORD=Tr0ub4dor&3

AWS Access Key        Line 7
  AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
```

Lines are truncated at 120 characters. Findings flagged only by file type or filename (e.g. `.pfx`, `id_rsa`) show a note in place of a snippet.

---

## Scan reports

Every completed scan is saved as a timestamped **JSON file** (`LeakLens_<timestamp>.json`) and a **SQLite database** (`LeakLens_<timestamp>.db`) in the `reports/` directory.

The **Reports** tab in the UI lists all saved reports — click any entry to reload its findings into the main view, complete with filtering, search, and the detail drawer.

The SQLite database enables fast paginated queries against historical scans without loading the entire result set into memory.

---

## Resume interrupted scans

If a scan is stopped before completion, LeakLens writes a checkpoint file to `reports/`. Enabling the **Resume** checkbox on the next scan of the same path will skip already-processed files and continue from where it left off.

---

## Multi-threaded scanning

The scanner uses a producer/consumer architecture:

- A single **walk thread** traverses the file tree and feeds a bounded queue
- A configurable number of **worker threads** (default 8, max 32) analyse files in parallel
- Results flow through an events queue back to the SSE generator

This allows I/O-bound SMB reads to overlap with CPU-bound pattern matching. The current scan rate (files/second) is shown live in the progress bar.

---

## SMB metadata in findings

When scanning a UNC path, findings include share context that is useful in an audit report:

```json
{
  "smbServer":       "fileserver01",
  "smbShare":        "\\\\fileserver01\\IT",
  "smbRelativePath": "scripts\\deploy.ps1",
  "lastModified":    "2024-11-14 08:23",
  "lastAccessed":    "2025-01-02 13:45"
}
```

The detail drawer also surfaces this information alongside tailored remediation advice that references the share name.

---

## Risk levels

| Level | Criteria |
|---|---|
| 🔴 HIGH | Confidence ≥ 8 — private key, plaintext password, AWS key, sensitive binary file |
| 🟡 MEDIUM | Confidence 5–7 — API key pattern, PSCredential, suspicious filename |
| 🟢 LOW | Confidence ≤ 4 — hash strings, low-signal patterns |

---

![LeakLens scan screenshot](Images/Home-scanned.png)

---

## API reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/scan` | Start a scan. Returns an SSE stream of events. |
| `POST` | `/api/scan/stop` | Stop the active scan. |
| `GET` | `/api/status` | `{scanning: bool, version: str}` |
| `POST` | `/api/shares` | Enumerate SMB shares on a host. |
| `GET` | `/api/scans` | List all SQLite-backed scan metadata. |
| `GET` | `/api/scans/<scan_id>/export` | Export all findings for a scan as JSON. |
| `GET` | `/api/findings` | Paginated findings query against a scan DB. |

### POST /api/scan — body parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `scanPath` | string | — | UNC or local path to scan (required) |
| `maxFileSizeMB` | int | 10 | Skip files larger than this |
| `workers` | int | 8 | Number of parallel worker threads (1–16) |
| `resume` | bool | false | Resume from the last checkpoint for this path |
| `username` | string | — | SMB username |
| `password` | string | — | SMB password |
| `domain` | string | — | SMB domain |

### GET /api/findings — query parameters

| Parameter | Default | Description |
|---|---|---|
| `scan_id` | — | Required. Timestamp ID of the scan (e.g. `20240101_120000`) |
| `page` | 0 | 0-based page number |
| `per_page` | 100 | Rows per page (1–500) |
| `risk` | ALL | Filter by risk: `HIGH`, `MEDIUM`, `LOW`, or `ALL` |
| `search` | — | Substring filter on filename or full path |

---

## Test server

A Samba container pre-loaded with intentionally dirty files is included so you can verify LeakLens works without touching real infrastructure. Requires Docker or Podman.

**Start it:**

```bash
# Linux / macOS
./testserver/start-testserver.sh

# Windows
testserver\start-testserver.bat
```

The container runs Samba on port **4445**. Mount the share locally, then point LeakLens at the mount path.

**Linux:**
```bash
sudo mkdir -p /mnt/testshare
sudo mount -t cifs //127.0.0.1/testshare /mnt/testshare -o port=4445,guest,vers=2.0
# Scan: /mnt/testshare
```

**macOS:**
```
open 'smb://127.0.0.1:4445/testshare'
# Scan: /Volumes/testshare (or wherever Finder mounts it)
```

**Windows:**
```cmd
net use Z: \\127.0.0.1\testshare "" /user:guest /port:4445
:: Scan: Z:\
```

**Stop it:**

```bash
./testserver/stop-testserver.sh   # Linux / macOS
testserver\stop-testserver.bat    # Windows
```

See [USAGE.md](USAGE.md) for the complete test server walkthrough.

Expected findings across the 8 test files:

| File | Patterns triggered |
|---|---|
| `deploy.ps1` | Plaintext Password, Connection String, PowerShell SecureString, Hardcoded PSCredential |
| `app.config` | Plaintext Password, Generic API Key/Token |
| `passwords.txt` | NTLM Hash |
| `.env` | AWS Access Key, Plaintext Password, Base64 Credential, Stripe API Key |
| `nightly-backup.bat` | Net Use Credential |
| `db_maintenance.py` | Plaintext Password, Bearer Token |
| `id_rsa` | Private Key Header |
| `project-notes.md` | *(clean — no findings)* |

---

## Running the tests

Install dev dependencies, then run pytest:

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -v
```

149 tests across three modules: pattern regexes, engine helpers, and API endpoints.
See [USAGE.md](USAGE.md) for a full walkthrough including the live test server.

---

## Project structure

```
LeakLens/
├── leaklens.py                 # Entry point — Flask server + all API routes
├── requirements.txt            # Pinned runtime dependencies
├── requirements-dev.txt        # Adds pytest for development
├── start.bat / start.sh        # Launchers
├── scanner/
│   ├── engine.py               # Scan orchestrator — walk, workers, SQLite, SSE
│   ├── content.py              # Detection helpers, scan_content(), build_finding()
│   ├── patterns.py             # 25 detection rules (pre-compiled)
│   ├── smb.py                  # smbprotocol helpers
│   ├── suppress.py             # .leaklensignore parser
│   └── checkpoint.py           # Resume checkpoint helpers
├── frontend/
│   ├── index.html              # Browser UI shell
│   └── Assets/
│       ├── app.js              # SSE client, virtual scroll, filters
│       └── styles.css
├── tests/
│   ├── test_patterns.py        # Positive/negative tests for all 25 patterns
│   ├── test_engine.py          # scan_content, build_finding, suppression helpers
│   └── test_api.py             # Flask endpoint tests
├── reports/                    # Auto-created: SQLite + JSON per scan
└── testserver/                 # Samba container for testing
```

---

## How it works

`leaklens.py` starts a Flask server that serves the frontend and exposes `POST /api/scan`. When a scan starts, a walk thread traverses the target path — local or SMB — feeding a bounded queue. A pool of worker threads analyses files in parallel, matching patterns, applying confidence scoring and suppression rules, and emitting findings as JSON events. The browser reads these as **Server-Sent Events** streamed directly from the POST response body.

Findings are persisted to a per-scan SQLite database as they arrive, enabling the paginated `/api/findings` endpoint to serve historical data efficiently without re-loading JSON reports.

---

## Images

![LeakLens Evidence](Images/Evidence.png)
![LeakLens Reports](Images/Reports.png)

---

## Legal

Run LeakLens only on systems and file shares you are authorized to access. Scanning reads file contents — ensure you have the appropriate permissions before use.

> LeakLens is open source and community-driven.
> Bug reports, feature requests, and PRs are welcome. Especially new detection patterns and test cases.
