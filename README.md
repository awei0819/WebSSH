# WebSSH — A Practical & Secure Browser-Based Shell Client

> **English** | [简体中文](README.zh-CN.md)

Connect to your servers from a browser: one-click connect from the host list, multi-tab terminals, and SFTP file upload/download.
The server side is just five pure-Python files under `src/` — no database, no frontend build step. Release packages bundle their own Python runtime: unzip and run.
Security comes built in — login authentication, per-user asset isolation, encrypted credential storage — safer than a bare terminal tool, far lighter than a bastion host.

## Quick Start (no Python install, no internet needed)

Release packages bundle a complete runtime — unzip and go:

| Platform | Package (version follows the code) | Launch |
|---|---|---|
| Windows x64 | `WebSSH_v2.0.0_win_x64.zip` | Unzip, double-click **`run.bat`** |
| Linux x86_64 (Kylin/CentOS/Ubuntu) | `WebSSH_v2.0.0_linux_x86_64.tar.gz` | `tar xzf … && cd WebSSH && sh run.sh` |
| Linux aarch64 (Phytium/Kunpeng) | `WebSSH_v2.0.0_linux_aarch64.tar.gz` | Same as above |
| macOS Apple Silicon | `WebSSH_v2.0.0_mac_arm64.tar.gz` | Same as above |

Open `https://127.0.0.1:8089/` in your browser (accept the self-signed certificate warning on first visit; LAN users go to `https://<your-ip>:8089/`).
Default account `admin / Admin#1234` — **change the password immediately after deployment**.

The package contains only: five app files starting with `main.py` + `runtime/` (Python runtime & dependencies) + `run.bat`/`run.sh` + `README` + `test_e2e.py` (fresh-machine self-check).

## Building Release Packages

```bash
python pack.py                          # default: win_x64 package
python pack.py --arch linux-x86_64      # other architectures as needed
python pack.py --arch linux-aarch64     # Phytium/Kunpeng
python pack.py --arch mac-arm64
python pack.py --arch all               # all of them
python pack.py --with-data              # add to any command: bundle data/ assets too
```

- The version number is taken from the `VERSION` variable in `src/core.py`; package names follow automatically
- Dependency wheels are downloaded from the **Tsinghua PyPI mirror** first, falling back to official PyPI
- Runtimes for every platform (Windows included) come from python-build-standalone (`stripped` builds preferred). **If GitHub is unreachable**, download the tar.gz manually in a browser, drop it into `build_cache/runtimes/` keeping the original name (containing `-install_only_stripped.tar.gz`), and rerun — it will be picked up automatically
- Runtimes and wheels are cached in `build_cache/`; repeated builds finish in seconds
- Artifacts are pruned: no stdlib test suite, tkinter, static libs, pip/setuptools, or debug symbols

## From Source (alternative; requires system Python 3.7+)

```bash
pip install -r requirements.txt
python src/main.py
# or run.bat (Windows) / run.sh (Linux/macOS) from the repo —
# run.sh creates an isolated .venv automatically (works with Kylin V10's Python 3.7)
```

## Runtime Options

```bash
python src/main.py             # default: HTTPS on 0.0.0.0:8089
python src/main.py --no-tls    # fall back to HTTP
# run.bat / run.sh pass arguments through, e.g.: sh run.sh --no-tls
```

- Bind address & port: edit `WEBSSH_HOST` / `WEBSSH_PORT` at the top of `run.bat` / `run.sh` (default `0.0.0.0:8089`; for local-only use set `WEBSSH_HOST` to `127.0.0.1`; setting the same environment variables directly also works)
- Behind a reverse proxy (Nginx etc.): the proxy must pass the original Host header (`proxy_set_header Host $host;`), otherwise the Origin check will reject the WebSocket; alternatively set `WEBSSH_ALLOWED_ORIGINS=https://your.domain` (comma-separated) to allow-list origins
- A self-signed certificate is generated on first start at `data/webssh_cert.pem` (10 years, SAN includes the machine's LAN IP)

## Built-in Security

- Login brute-force protection: 5 consecutive failures lock the account for 5 minutes (unknown usernames count too)
- Versioned login sessions: changing a password invalidates all of that user's existing cookies immediately
- Security response headers: nosniff / DENY / CSP / no-store, plus HSTS over HTTPS; server fingerprint hidden
- Host passwords/private keys are encrypted at rest with Fernet; no endpoint ever returns plaintext credentials (quick-connect only sends a host_id)
- File transfers are bound to the terminal session (random token, invalidated on disconnect)
- Unknown host keys are rejected by default; with "trust" checked, fingerprints are recorded TOFU-style and any later change is rejected
- TLS 1.2/1.3 only

## Login & Users

- Multi-user: admins can add users, reset passwords, and delete users in Settings (the `admin` account cannot be deleted)
- Password change: regular users must provide the old password, admins are exempt; re-login required afterwards
- Assets are per-user: each user only sees and connects to their own hosts
- Reset all accounts: delete `data/auth.json` and restart

## Migration & Data

| File | Purpose | Notes |
|---|---|---|
| `data/hosts.json` | Host assets (per-owner, credentials encrypted) | Migrate together with the package |
| `data/secret.key` | Credential encryption key | ⚠️ Must stay paired with hosts.json; **anyone who gets these files can decrypt the credentials** — trusted channels only |
| `data/auth.json` | Platform account hashes | Optional; a default admin is rebuilt if absent |
| `data/known_hosts` | TOFU fingerprints | Optional; rebuilt automatically if absent |

## Tests

```bash
python test_e2e.py                  # or from a package: runtime/python3 (or python.exe); ~30s full-chain self-check
python -m ruff check .              # static checks (pip install ruff; rules in .ruff.toml)
```
