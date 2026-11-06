# WebSSH Release Process (GitHub Release)

> Scenario: publish the four platform packages to GitHub for direct download.
> Why the command line: GitHub's web upload caps attachments at 25 MB per file and our
> packages run 20–70 MB, so we go through the API channel (2 GB per file) with the
> official `gh` CLI.

## 1. Install GitHub CLI (once per machine)

Either:

```powershell
winget install --id GitHub.cli
```

or download the MSI from <https://github.com/cli/cli/releases/latest>
(`gh_x.x.x_windows_amd64.msi`) and install it (for Server editions without winget).

**Open a new terminal afterwards** — PATH is loaded at shell start, so an old window
keeps reporting "gh is not recognized". Verify:

```bash
gh --version
```

## 2. Authenticate (once per machine)

```bash
gh auth login
```

Choose `GitHub.com` → `HTTPS` → `Login with a web browser`; a one-time code is shown,
press Enter and complete the authorization in the browser.

## 3. Publish a Release

### 1. Build the four packages (from the project root)

```bash
python pack.py --arch all
```

Artifacts (the version comes from the `VERSION` variable in `src/core.py`):

```
WebSSH_v2.0.0_win_x64.zip
WebSSH_v2.0.0_linux_x86_64.tar.gz
WebSSH_v2.0.0_linux_aarch64.tar.gz
WebSSH_v2.0.0_mac_arm64.tar.gz
```

Every build runs a completeness verification (critical dependencies / launchers /
permissions); a failed check fails the build.

### 2. Upload (run in the directory containing the packages, single line)

```bash
gh release create -R awei0819/WebSSH v2.0.0 WebSSH_v2.0.0_win_x64.zip WebSSH_v2.0.0_linux_x86_64.tar.gz WebSSH_v2.0.0_linux_aarch64.tar.gz WebSSH_v2.0.0_mac_arm64.tar.gz -t "v2.0.0" -n "A practical & secure browser-based shell client. Unzip and run."
```

| Option | Meaning |
|---|---|
| `-R awei0819/WebSSH` | Target repo (required when not run inside a clone) |
| `v2.0.0` | Tag name; created automatically if it does not exist |
| the four files | Attachments (API channel, 2 GB each) |
| `-t` | Release title |
| `-n` | Description; use `-F release_notes.md` for longer text |

### 3. Verify

On success the command prints the release URL. Direct download links look like:

```
https://github.com/awei0819/WebSSH/releases/download/v2.0.0/WebSSH_v2.0.0_win_x64.zip
```

usable with `curl -LO` / `wget`. Note: **releases of a private repo are visible to
collaborators only** — make the repo public first if you need public downloads
(Settings → General → Danger Zone).

## 4. Release cadence for future versions

1. Update `VERSION = "v2.0.1"` in `src/core.py`
2. `python pack.py --arch all` to build the new packages (names follow the version)
3. Commit and push
4. `gh release create -R awei0819/WebSSH v2.0.1 WebSSH_v2.0.1_*.zip ...` (same as above)

Keep three places in sync: the code variable / package names / the tag.

## 5. Troubleshooting

| Symptom | Fix |
|---|---|
| Web upload fails with `File size too big: 25 MB are allowed` | Hard limit of the web channel; use the gh command in this doc |
| `'gh' is not recognized` | Open a NEW terminal after installing; if it still fails, the install did not succeed |
| `gh release create` reports an auth failure | Re-run `gh auth login`, or check `gh auth status` |
| Uploaded the wrong thing | `gh release delete v2.0.0 -R awei0819/WebSSH --yes` then recreate; or `gh release upload v2.0.0 files --clobber -R ...` to overwrite the attachments |
