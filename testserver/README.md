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

After starting, mount the share and scan the mapped drive:
```cmd
net use Z: \\127.0.0.1\testshare /user:guest "" /p:no /port:4445
```
Then point LeakLens at `Z:\`

### Linux / macOS
```bash
chmod +x start-testserver.sh stop-testserver.sh
./start-testserver.sh
./stop-testserver.sh
```

After starting, mount the share:
```bash
# Linux
sudo mount -t cifs //127.0.0.1/testshare /mnt/testshare -o port=4445,guest,vers=2.0

# macOS
open 'smb://127.0.0.1:4445/testshare'
```
Then point LeakLens at the mounted path.

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
