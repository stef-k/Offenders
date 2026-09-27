# Offenders (Fail2Ban TUI)

A **Textual**-based terminal UI (TUI) that reads Fail2Ban logs and shows:

- **Top banned IPs** (count + country + ASN/Org)
- **Current active jails**
- **Active bans per jail**
- **Last bans** from the selected log period
- **WHOIS / RDNS** for the currently selected IP (via system tools)

Designed for Linux servers running Fail2Ban (e.g. Ubuntu).

## Screenshot

![Offenders TUI screenshot](offenders-screenshot.jpg)

## Requirements

- Python **3.12+**; the supported server/development baseline is Ubuntu **24.04 LTS** with Python **3.12**.
- Fail2Ban **1.1.x** installed separately and logging to:
  - `/var/log/fail2ban.log` (plus rotated logs)
- Ability to run `fail2ban-client` (the app uses `sudo fail2ban-client ...`)

### Python dependencies

This project depends on:

- `textual>=8.2.8,<9` (the supported Textual 8 release line)
- (optional) `geoip2` — only if you want Python-based MMDB lookups; otherwise the app falls back to `mmdblookup` if present.

From the repository root, install into a virtual environment (on Ubuntu, install
`python3-venv` first if needed). `pyproject.toml` owns the dependency bounds:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Optional:

```bash
python -m pip install -e ".[geoip]"
```

The optional extra bounds `geoip2` to `>=5.3,<6`. A base install does not require
GeoIP Python packages or database downloads. For a non-editable installation,
use `python -m pip install .`; `python -m pip install -r requirements.txt` remains
a compatible alternative. Editable installation keeps changes to the documented
configuration constants effective when running the installed command.

## System tools (optional but recommended)

These are used for enrichment and convenience actions:

- `mmdblookup` (optional) — used when `geoip2` isn't installed
- `whois` (optional) — enables the **WHOIS** popup (`w`)
- `dig` (optional) — enables better **RDNS** output (`d`), otherwise the app falls back to `getent hosts`

On Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y mmdb-bin whois dnsutils
```

## GeoIP / ASN database files (required for enrichment)

This app **does not download GeoIP/ASN data**. It expects **pre-downloaded** MaxMind-style **MMDB** files on the host.

By default, the script reads these stable filenames:

```python
GEO_COUNTRY_DB = "/usr/share/GeoIP/dbip-country-lite.mmdb"
GEO_ASN_DB     = "/usr/share/GeoIP/dbip-asn-lite.mmdb"
```

If the files are missing, the UI still runs, but the country/ASN fields will show fallback values like **"Unknown"** / **"No ASN"**.

### Included updater script (DB-IP Lite) — Python

This repo includes a helper script to download and refresh the free **DB-IP Lite** databases monthly and maintain stable symlinks:

- `update_geoip_db.py` (Python)

What it does:

- downloads the monthly `.mmdb.gz` files (Country + ASN) from DB-IP
- decompresses them
- installs them into `/usr/share/GeoIP`
- updates these symlinks so the app can always read consistent paths:
  - `/usr/share/GeoIP/dbip-country-lite.mmdb`
  - `/usr/share/GeoIP/dbip-asn-lite.mmdb`
- prunes old MMDB files by default, keeping **only the latest 2** per type (current + previous rollback)

**Prereqs:**

- Python **3.x** (tested with system Python on Ubuntu; e.g. 3.12)
- root privileges to write into `/usr/share/GeoIP`

#### Install / run manually

Copy it somewhere in PATH (optional but convenient):

```bash
sudo cp update_geoip_db.py /usr/local/bin/update_geoip_db.py
sudo chmod +x /usr/local/bin/update_geoip_db.py
```

Run it:

```bash
sudo /usr/bin/python3 /usr/local/bin/update_geoip_db.py
```

Sanity check:

```bash
ls -lh /usr/share/GeoIP/dbip-*-lite*.mmdb
readlink -f /usr/share/GeoIP/dbip-country-lite.mmdb
readlink -f /usr/share/GeoIP/dbip-asn-lite.mmdb
```

#### Run monthly via cron (recommended: log to journald with a stable tag)

Instead of writing log files and dealing with logrotate, you can pipe output into `logger` and filter by tag via `journalctl`.

Edit root’s crontab:

```bash
sudo crontab -e
```

Add:

```cron
@monthly /usr/bin/python3 /usr/local/bin/update_geoip_db.py 2>&1 | /usr/bin/logger -t dbip-geoip-updater
```

View logs:

```bash
journalctl -t dbip-geoip-updater --since "90 days ago"
```

#### Pruning behavior

By default, the updater keeps **the latest 2** MMDB files per type (Country/ASN) and deletes older ones. This keeps a “previous month” rollback without accumulating files.

To disable pruning:

```bash
sudo /usr/bin/python3 /usr/local/bin/update_geoip_db.py --no-prune
```

To keep more history (e.g. last 6):

```bash
sudo /usr/bin/python3 /usr/local/bin/update_geoip_db.py --keep-last 6
```

DB-IP Lite downloads page: <https://db-ip.com/db/lite.php>

### Avoid sudo password prompts

Because the app calls `sudo fail2ban-client ...`, you’ll typically want to allow passwordless access for `fail2ban-client` via `sudoers`.

Edit safely with `visudo` and add something like:

```text
stef ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client
```

Adjust the username and path to `fail2ban-client` as needed:

```bash
which fail2ban-client
```

## Run

Activate the environment used for installation, then run:

```bash
source .venv/bin/activate
offenders
```

From the checkout, `python offenders.py` and `./offenders.py` also work with that
environment active. Run as the user with log-read and Fail2Ban permissions; the
application still invokes `sudo fail2ban-client` for jail status.

## Key bindings

Global:

- `q` — quit
- `r` — refresh now
- `t` — toggle table cursor mode (row/cell)
- `c` or `x` — copy selection
  - in **row** mode: copies the entire row (tab-separated)
  - in **cell** mode: copies the current cell

Network tools (on selected IP):

- `w` — WHOIS (requires `whois`)
- `d` — reverse DNS
  - uses `dig -x` if available, otherwise falls back to `getent hosts`

Modal popup (WHOIS/RDNS output):

- `esc` or `q` — close
- `c` — copy output (prints to stdout if clipboard isn't available)

## Configuration

Edit these constants in the script:

- `TOP_COUNT` — number of offenders to show
- `LOOKBACK_DAYS` — how many days of bans to include (`0` = all logs)
- `IGNORE_PRIVATE` — skip private/loopback/link-local IPs
- `CHECK_INTERVAL_SECONDS` — refresh interval

## License

MIT — see [LICENSE](LICENSE).

## Development tests

After installing the project in your virtual environment, run:

```bash
python -m unittest discover -s tests -v
```

The suite uses Python's standard-library `unittest`, temporary log files, and
local Fail2Ban status fixtures. Running it requires no daemon, root access,
network access, or GeoIP databases. It covers ban recognition, IP normalization
and local-address filtering, numeric gzip rotation ordering, inclusive calendar
lookback boundaries (`0` includes all dates), and jail/table parsing.

The suite also mounts the real Textual dashboard with a fixture report, checks
table rendering and cursor-mode switching, and quits through the keyboard binding.
It does not require a running Fail2Ban daemon.

### Runtime qualification

Fresh installation and the offline suite were validated on Ubuntu 24.04 with
Python 3.12.3 and Textual 8.2.8, including the optional GeoIP extra. Both the
installed command and executable source script rendered and exited successfully
in a local pseudo-terminal without a live Fail2Ban daemon. The jail status fields used by Offenders
(`Jail list` and `Currently banned`) match Fail2Ban 1.1.0 client formatting.
Existing UI compatibility fallbacks remain because the parsing tests from #12
do not protect those UI paths.

Live server qualification still requires running `fail2ban-client --version`,
checking `sudo fail2ban-client status` and `sudo fail2ban-client status <jail>`,
and launching `offenders` in a terminal with real logs. Verify that the dashboard
shows the same jails and active-ban counts, refreshes with `r`, and exits with `q`.
Offline tests do not establish server permissions, real log access, or live
Fail2Ban integration.
