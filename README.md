# LeakLens

![LeakLens Banner](Images/leaklens-banner.svg)

**The file share credential scanner for pentesters and security auditors.**

Tools like truffleHog and gitleaks are built for git repositories and much more, but a bit more complex to use (Be sure to check out those repo's if you need more feature rich tools). LeakLens scans `\\server\share` in a simple way. Without mounting, with confidence-scored findings streamed to a browser in real time.

Born from a pentest finding: a domain admin password sitting in a plaintext `.ps1` file on an open file share, readable by every user in the domain. LeakLens exists to find those before an attacker does.

---

## What it does

Scans Windows file shares (and local paths) for exposed credentials:

- Connects directly to SMB/UNC paths — no `net use`, no manual mount
- Enumerates shares on a server with one click
- Scans text files for passwords, hashes, keys, tokens, and connection strings
- Flags sensitive file types (`.pfx`, `.ppk`, `.kdbx`, `.pem`, ...) and risky filenames (`id_rsa`, `credentials`, `.env`, ...)
- Scores every finding 1–10 so you spend time on what matters
- Streams results to a browser UI in real time
- Saves a timestamped JSON report of every scan

---

## Requirements

- Python 3.11+
- Dependencies install automatically on first run:
  - `flask>=3.0`
  - `smbprotocol>=1.13`

No Node.js. No PowerShell.

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

---

## Scanning a file share

1. Enter a UNC path — `\\server\share` — or a local path
2. For UNC paths the **SMB Credentials** panel appears automatically
   - Leave blank to try guest/anonymous access first
   - Or enter domain credentials for authenticated scans
3. Click **Discover Shares** to enumerate all visible shares on a server
4. Set the max file size to scan (default: 10 MB)
5. Click **Start Scan**
6. Findings stream in as they are found — click any row for detail and remediation advice

---

## What it detects

### Content patterns

| Pattern | Examples | Confidence |
|---|---|---|
| Plaintext Password | `password=`, `"password": "..."`, `DB_PASSWORD=` | 8/10 |
| Connection String | Embedded passwords in connection strings | 8/10 |
| NTLM / LM Hash | `lm_hash:ntlm_hash` pairs | 7/10 |
| Bcrypt Hash | `$2a$`, `$2b$`, `$2y$` | 7/10 |
| Base64 Credential | Base64 values next to credential keywords | 7/10 |
| AWS Access Key | `AKIA…` | 9/10 |
| API Key / Bearer Token | Key assignments and `Bearer` tokens | 6/10 |
| Private Key Header | `-----BEGIN … PRIVATE KEY-----` | 10/10 |
| Net Use Credential | `net use /user:` commands | 7/10 |
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
| 7–8 | High confidence — plaintext password, NTLM hash, connection string |
| 5–6 | Moderate — API key pattern, PSCredential, suspicious filename |
| 3–4 | Low signal — hash strings that could be checksums rather than credentials |

Confidence is reduced automatically for files in `docs/`, `examples/`, `test/`, and similar directories. Files where only generic hash patterns match are downgraded to LOW with a note.

---

## False positive reduction

- Common placeholders (`changeme`, `example`, `${password}`, `***`, etc.) are excluded from password matches
- Docs and example directories reduce confidence by 3 points automatically
- Hash-only findings are demoted to LOW with the note: *"Hash strings detected — verify these are credential hashes and not integrity checksums."*

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

## Test server

A Samba container pre-loaded with intentionally dirty files is included so you can verify LeakLens works without touching real infrastructure. Requires Docker or Podman.

**Start it:**

```bash
# Linux / macOS
./testserver/start-testserver.sh

# Windows
testserver\start-testserver.bat
```

**Scan it** — point LeakLens at `\\127.0.0.1\testshare` with blank credentials (guest access). No mount required.

**Stop it:**

```bash
./testserver/stop-testserver.sh   # Linux / macOS
testserver\stop-testserver.bat    # Windows
```

Expected findings across the 8 test files:

| File | Patterns triggered |
|---|---|
| `deploy.ps1` | Plaintext Password, Connection String, PowerShell SecureString, Hardcoded PSCredential |
| `app.config` | Plaintext Password, Generic API Key/Token |
| `passwords.txt` | NTLM Hash |
| `.env` | AWS Access Key, Plaintext Password, Base64 Credential |
| `nightly-backup.bat` | Net Use Credential |
| `db_maintenance.py` | Plaintext Password, Bearer Token |
| `id_rsa` | Private Key Header |
| `project-notes.md` | *(clean — no findings)* |

---

## Project structure

```
LeakLens/
├── leaklens.py            # Entry point — Flask server + SSE streaming
├── scanner/
│   ├── engine.py          # Scanning logic — local and SMB paths
│   ├── patterns.py        # Detection rules with confidence scores
│   └── smb.py             # SMB/UNC helpers (smbprotocol)
├── frontend/
│   └── index.html         # Browser UI
├── requirements.txt
├── start.bat              # Windows launcher
├── start.sh               # Linux/macOS launcher
├── reports/               # JSON scan reports (auto-created)
└── testserver/            # Samba container for testing
```

---

## How it works

`leaklens.py` starts a Flask server that serves the frontend and exposes `POST /api/scan`. When a scan starts, a background thread runs `scanner/engine.py`, which walks the target path — local or SMB — matches patterns, applies confidence scoring and suppression rules, and yields findings as JSON. The browser reads these as **Server-Sent Events** streamed directly from the POST response body.

---

## Legal

Run LeakLens only on systems and file shares you are authorized to access. Scanning reads file contents — ensure you have the appropriate permissions before use.
