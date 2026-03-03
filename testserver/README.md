# LeakLens — Test File Server

A lightweight Samba container pre-loaded with intentionally unsafe files to test LeakLens against without touching real infrastructure.

Runs on port **4445** by default to avoid conflict with the Windows SMB service on port 445.

---

## Requirements

Docker or Podman — either works. The start scripts detect whichever is available.

---

## Usage

### Windows
```
start-testserver.bat   ← start
stop-testserver.bat    ← stop
```

### Linux / macOS
```bash
chmod +x start-testserver.sh stop-testserver.sh
./start-testserver.sh
./stop-testserver.sh
```

---

## Connecting LeakLens to the test server

No mounting required. LeakLens connects directly over SMB using `127.0.0.1:4445`.

### Via the UI (recommended)

1. Start LeakLens (`start.sh` / `start.bat` or `python3 leaklens.py`)
2. Open **http://localhost:3000** in your browser
3. Click **⬡ SMB: Browse Shares & Credentials** in the Scan Configuration panel
4. Enter `127.0.0.1:4445` in the **Server / Host** field
5. Leave Username and Password blank (the share allows guest/anonymous access)
6. Click **⬡ Discover Shares** — `testshare` appears in the list
7. Click **testshare** to select it — the Path field is populated automatically
8. Click **Start Scan**

### Via the CLI

```bash
python3 leaklens.py scan --path "\\\\127.0.0.1\\testshare" --smb-port 4445
```

---

## Test Files Included

| File | Patterns triggered |
|---|---|
| `deploy.ps1` | Plaintext password, PSCredential, connection string |
| `app.config` | Plaintext password, API key, bearer token |
| `passwords.txt` | NTLM hashes, plaintext passwords |
| `.env` | AWS access key, plaintext passwords, API key |
| `nightly-backup.bat` | Net use credential |
| `db_maintenance.py` | Plaintext password, bearer token |
| `id_rsa` | Private key header, risky filename |
| `project-notes.md` | Clean — should produce no findings |

---

## Notes

- The share is read-only and requires no authentication (guest access)
- All credentials in the test files are completely fake
- The container is stateless — stopping it removes everything
