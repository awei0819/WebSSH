# WebSSH — Browser-Based Shell Client

> **English** | [简体中文](README.zh-CN.md)

Connect to your servers from a browser: one-click connect from the host list, multi-tab terminals, and SFTP file upload/download.

## Launch

| OS | How |
|---|---|
| Windows | Double-click **`run.bat`** |
| Linux / macOS | Run **`sh run.sh`** in a terminal (run.sh handles macOS quarantine attributes and executable bits automatically; if the system still says "cannot verify developer": System Settings → Privacy & Security → Open Anyway) |

Then open `https://127.0.0.1:8089/` (others on the LAN use `https://<your-ip>:8089/`).

- The browser will warn about the certificate on first visit (self-signed) — choose "Advanced → Proceed"
- To fall back to HTTP: `run.bat --no-tls` / `sh run.sh --no-tls`
- Bind address & port: edit `WEBSSH_HOST` / `WEBSSH_PORT` at the top of `run.bat` / `run.sh` (default `0.0.0.0:8089`; for local-only use set `WEBSSH_HOST` to `127.0.0.1`)

## First Login

Default account `admin`, default password `Admin#1234` — **change it immediately after login** (⚙ Settings at the bottom of the sidebar → Change Password; you will be asked to log in again).

## Feature Tour

- **Host management**: Settings ⚙ → Hosts, add servers (IP/port/username/password or private key); click a host name in the list to connect
- **Terminal**: multi-tab; right-click a tab to duplicate/reconnect/close; disconnected tabs turn red and can reconnect
- **Files**: after connecting, click « on the right of the tab bar to open the file panel — browse/upload/download/delete, with multi-task progress and cancel
- **Multi-user**: admins can add users in Settings; each user only sees their own hosts

## Data & Backup

All runtime data lives in the `data/` directory inside the package (next to `run.bat`/`run.sh`):

| File | Description |
|---|---|
| `data/hosts.json` | Host assets (credentials encrypted at rest) |
| `data/secret.key` | Encryption key — **keep it paired with hosts.json; anyone holding both files can decrypt the passwords** |
| `data/auth.json` | Platform accounts (hashed) |

**Backup**: copy the whole `data/` directory. **Migration**: unzip the package on the new machine and overwrite `data/` with your backup — all accounts and hosts are restored.

## Self-check

After deploying to a new machine you can run a full integrity self-check (~30 seconds, touches no real servers):

```bash
runtime\python.exe test_e2e.py     # Windows
runtime/bin/python3 test_e2e.py    # Linux / macOS
```
