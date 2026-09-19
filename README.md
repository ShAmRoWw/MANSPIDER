# MANSPIDER — ShAmRoWw fork

A Linux-focused fork of [MANSPIDER](https://github.com/blacklanternsecurity/MANSPIDER),
maintained by [ShAmRoWw](https://github.com/ShAmRoWw/MANSPIDER).
Find sensitive files and credentials on SMB shares during authorized security
assessments, using filename filters, content searches, and configurable rules.

## What this fork adds

- 251 built-in rules for credential artifacts, keys, tokens, configuration files,
  and other sensitive data, with severity, confidence, and match context.
- Durable SQLite sessions, automatic session discovery, and resumable scans.
- A local web viewer with live results, filters, manual-review marks,
  English/Russian languages, and light/dark themes.
- Explicit content-analysis outcomes, coverage reports, progress estimates,
  and passive SMB metrics.
- Reused SMB connections, batched local processing, and additional read-only
  safeguards. Higher throughput can still increase peak server load.

## Installation

Requirements: Linux, Git, and [uv](https://docs.astral.sh/uv/getting-started/installation/).
Use a local filesystem and run as your normal user; `sudo` is not needed.
Install **this fork**, including the web viewer, in two commands:

~~~bash
git clone https://github.com/ShAmRoWw/MANSPIDER.git
bash MANSPIDER/install.sh
~~~

The installer uses Python 3.12 (downloaded by uv if needed), checks `uv.lock`,
and installs the locked runtime dependencies into an isolated uv tool environment.
Both `manspider` and `manspider-web` are available from **any directory** for your
user, without activating a virtual environment. If the installer updates your
shell's `PATH`, open a new terminal or use the command it prints.

The installed copy does not depend on keeping the checkout in place. Existing
commands installed by another package manager are not forcibly overwritten.
For updates, update the checkout and rerun `bash install.sh` from it; this also
applies the new lockfile. Uninstall with `uv tool uninstall man-spider`; saved
scan results are not removed.

For development instead, run `uv sync --locked --extra web --python 3.12` from
the checkout and use `.venv/bin/manspider` / `.venv/bin/manspider-web`.

Tests that require the optional local `testdata/` or `tools/` directories are
skipped when those directories are absent from the public checkout. Other tests
remain available; missing files inside an existing fixture directory still fail.

Optional system tools for image OCR and legacy Office extraction on Debian/Kali:

~~~bash
sudo apt install tesseract-ocr libreoffice
~~~

Missing extraction dependencies are reported per file; other scan work continues.

### Docker

Build from this checkout and explicitly select the resulting image:

~~~bash
docker build -t manspider-fork .
MANSPIDER_IMAGE=manspider-fork ./manspider.sh --help
~~~

The helper stores results in a persistent local Docker volume. Always set
`MANSPIDER_IMAGE`: the helper's fallback image belongs to upstream. The Docker
build includes the scanner, not the optional web viewer.

## Quick start

Scan a host with the built-in rules:

~~~bash
manspider 192.0.2.10 -d EXAMPLE.TEST -u auditor -p 'PASSWORD' --builtin-rules
~~~

Replace the target and credentials with your authorized scope. Targets can be
IP addresses, hostnames, CIDR ranges, or a text file such as `targets.txt`
containing one target per line, without comments. Local directories are also
supported and do not require SMB credentials.

The built-in rules are opt-in: use `--builtin-rules`, custom `--rules` files,
or explicit search filters. Credential preflight runs before the configuration
review; the main scan starts only after confirmation. Add `--yes` for unattended
runs, and `--no-resume-prompt` to explicitly start a fresh session.

### Search examples

~~~bash
# Metadata only: find matching extensions without reading file content.
manspider targets.txt -d EXAMPLE.TEST -u auditor -p 'PASSWORD' -e kdbx pem pfx

# Search selected text files for credential assignments.
manspider targets.txt -d EXAMPLE.TEST -u auditor -p 'PASSWORD' \
  -e txt ini conf config -c '(?i)(password|secret|token)\s*[:=]\s*\S+'

# Analyze a local directory with the built-in rules.
manspider ./documents --builtin-rules
~~~

Matching files are **not saved as copies by default**. Add `--download` to save
them locally. Content rules still read files for analysis without this option.
The former `-n` / `--no-download` options have been removed.

### Key defaults

| Setting | Default | Option |
| --- | --- | --- |
| Directory depth | 15 | `-m` |
| Content-read and saved-copy size limit | 10 MiB | `-s` |
| Global SMB worker budget | 5 | `-t` |
| Maximum simultaneous SMB sessions per host | 4 | `--max-sessions-per-host` |

Metadata-only findings have no global size limit; exclusions and rule-specific
size conditions still apply. `IPC$`, `C$`, `ADMIN$`, and `PRINT$` are excluded by
default. See `manspider --help` for filters, authentication methods, and overrides.

## Sessions and resume

Sessions are created automatically in `~/.local/state/manspider/scans`, respecting
`XDG_STATE_HOME`. Set `MANSPIDER_STATE_DIR` to choose another local directory.
Each invocation has its own text log beside the SQLite session. SMB metrics and
the coverage-gap report are stored there too; add `--json` for a findings export.

Later interactive launches offer eligible unfinished sessions, newest first.
You can also resume explicitly by repeating the original scope and search
configuration and adding `--resume`:

~~~bash
manspider 192.0.2.10 -d EXAMPLE.TEST -u auditor -p 'PASSWORD' --builtin-rules \
  --resume /path/to/scan.sqlite3
~~~

Resume does not fill in the command's targets, credentials, or filters for you.
Normal resume continues unfinished work without revisiting unrelated completed
subtrees. Add `--refresh-resume` to enumerate the scope again for new or changed
files; unchanged completed files are still reused. Start a new scan to apply
changed rules or extraction behavior to all files.

## Local web viewer

Run separately from the scanner, in another terminal:

~~~bash
manspider-web
~~~

Open [http://127.0.0.1:8765/](http://127.0.0.1:8765/). For an explicit session,
use `manspider-web --state /path/to/scan.sqlite3`.

The viewer shows saved results while scans run, including elapsed time for the
current main-scan invocation and an approximate remaining time. Timing snapshots
refresh during scanning; estimates may change as more directories are discovered.
Resume starts a new elapsed-time counter, excluding downtime and earlier attempts.

Review marks are stored separately
and do not delete findings.

## Operational safety

- Scan only systems you are authorized to assess. Use a read-only account where possible.
- MANSPIDER requests read-only access to scanned files; it does not request file
  creation, modification, renaming, deletion, or permission changes on SMB shares.
- Rule evaluation and extraction run locally. Found credentials are not used to
  authenticate anywhere or submitted to online validation services.
- Cross-server DFS referrals are blocked by default. `--allow-external-dfs` can
  extend traversal beyond the supplied targets; enable it only for authorized
  backends. DNS and Kerberos may contact configured infrastructure services.
- Read-only does not mean zero impact. Reads can update server audit/access
  records and recall offline/HSM data. Such files remain readable by default,
  with a full-path warning when recall flags are observed. Concurrency limits
  are not request-rate limits.

## Documentation

- [Changes from upstream](CHANGES_FROM_ORIGINAL_MANSPIDER_EN.md)

## Credits and license

Original MANSPIDER: **TheTechromancer / BLS OPS LLC**.
Fork and modifications: **ShAmRoWw**.
[Snaffler](https://github.com/SnaffCon/Snaffler) is acknowledged as a reference
for rule coverage and design; it is not a runtime dependency.

Licensed under [GNU GPL v3](LICENSE). Original attribution is preserved.
