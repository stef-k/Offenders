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
- Fail2Ban **>= 1.0.2** installed separately (production baseline: **1.0.2**;
  compatibility currently qualified against the 1.0.x and 1.1.x status contracts
  used by Offenders) and logging to:
  - `/var/log/fail2ban.log` (plus rotated logs)
- Ability to run `fail2ban-client` (the app uses `sudo -n fail2ban-client ...`)

### Python dependencies

This project depends on:

- `textual>=8.2.8,<9` (the supported Textual 8 release line)
- `maxminddb>=3.1,<4` — direct generic MMDB reads, including a pure-Python backend;
  no system lookup binary is needed.

## Install and upgrade

The supported application distribution is PyPI with pipx on Ubuntu 24.04 /
Python 3.12. **The first PyPI release is pending final qualification (#48); the
index install commands below become usable after that release is published.**
Until then, use the source workflow below or a locally built wheel.

```bash
sudo apt-get update
sudo apt-get install -y pipx
pipx ensurepath
# Open a new login shell after ensurepath, then:
pipx install offenders
command -v offenders
offenders
```

For subsequent releases and removal:

```bash
pipx upgrade offenders
pipx uninstall offenders
```

pipx isolates Python dependencies. Fail2Ban, log access, and optional host tools
remain system responsibilities. Installation does not download GeoIP databases;
data stays in the existing user-owned XDG location outside the package.

Older standalone copies and their separate virtual environments are left intact.
Before switching, record the old executable path and retain its environment for
rollback. After installation, use `command -v offenders` (and `type -a offenders`
in Bash) to check for an older command earlier on PATH. Deliberately adjust PATH
or invoke the pipx executable by its reported path, then run `offenders geoip
status` and the dashboard. Do not remove the old installation until the new one
is verified. Rollback means restoring the old command resolution and environment;
package uninstall does not delete GeoIP data. Production cutover belongs to #70.

### Source and development installs

From the repository root (install `python3-venv` on Ubuntu if needed):

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

`pyproject.toml` owns the dependency bounds. A non-editable source install uses
`python -m pip install .`; `python -m pip install -r requirements.txt` remains
compatible. Editable installation keeps changes to documented configuration
constants effective. For local application isolation, `pipx install .` is also
available. See [release preparation](RELEASING.md) for wheel/sdist validation and
the maintainer-only publishing setup.

## System tools (optional but recommended)

These are used for enrichment and convenience actions:

- `whois` (optional) — enables the **WHOIS** popup (`w`)
- `dig` (optional) — enables better **RDNS** output (`d`), otherwise the app falls back to `getent hosts`

On Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y whois dnsutils
```

## GeoIP / ASN database files (required for enrichment)

GeoIP enrichment is optional. Run these commands as your normal user:

```bash
offenders                       # unchanged dashboard launch
offenders geoip status          # read-only local health, policy, last outcome
offenders geoip update          # explicit network download and activation
offenders geoip auto on         # opt in to future automatic checks
offenders geoip auto off        # default; disable future automatic checks
```

Data lives in `$XDG_DATA_HOME/offenders/geoip`, or
`~/.local/share/offenders/geoip` when unset. No sudo, cron, package installation,
or system service change is needed. Run the CLI and dashboard with the same XDG
environment. There is no arbitrary URL or system-target override.

The updater streams Country and ASN from the fixed DB-IP Lite HTTPS source.
Only a 404 permits falling back to the previous month, always for the whole pair.
Connection and individual socket reads have a 30-second timeout; each download
is limited to 128 MiB compressed and 512 MiB decompressed. Redirects are rejected.
Malformed/truncated gzip and invalid or wrong-role MMDBs fail before activation.

Validated data is installed in `generations/YYYY-MM-<unique-id>/`; one atomic
`current` symlink replacement activates both files. Updates hold a Linux advisory
writer lock. Readers continue using the previous files during acquisition and
refresh against the new generation on the next report, without restarting.
Current and the immediately previous complete generation are retained; only
older complete engine-owned generations are pruned after activation. Failed
acquisition leaves the previous active generation untouched. An activation that
succeeds but encounters housekeeping failure is reported explicitly as activated.

`offenders_geoip.py` owns source selection, health, MMDB readers and the bounded
2,048-entry cache per database. Both managed candidate paths are pinned to one
`current` target during refresh. Existing flat XDG files remain readable when no
`current` symlink exists. Missing/unhealthy preferred data falls back independently
to read-only `/usr/share/GeoIP/dbip-{country,asn}-lite.mmdb` files. Neither updates
nor pruning modify legacy system files. Status reports each source and candidate
health, including fallback failures, along with the active generation and policy.

`state.json` records opt-in (default off), last check time, and outcome. The shared
engine performs a locked automatic check once after dashboard mount when enabled.
Disabled or less-than-24-hour checks do not access the network. A successfully
activated current UTC month is not downloaded again automatically that month;
a previous-month publication fallback can retry after 24 hours. Manual updates
always run and also record check time. The 30-second report timer never checks
for updates. Import, lookup, and status never download.

Press **g** for focused GeoIP diagnostics, **u** for an explicit background Update
now, and **a** to persist automatic updates on/off (default off; enabling takes
effect at the next launch). Escape or q closes diagnostics. The view shows each
source, reader, path, generation, local age, policy and latest update outcome.
The first explicit update consents to downloading into user-owned storage.
A successful activation reloads health and requests one normal report refresh;
if collection is already running, the next normal refresh picks it up.

A separate dashboard line warns about unavailable Country/ASN sources or active
files older than **62 days**. Local age is only a warning; readable data remains
usable. Healthy legacy fallback and healthy-but-unmapped addresses do not cause
a global warning. Report freshness/degraded status remains independent. Failed
updates retain usable active data and show their error separately in diagnostics.
`offenders_geoip_ui.py` owns this focused UI and its background actions.

`update_geoip_db.py` is now a thin rootless compatibility wrapper. Its old
system-target, root-cron, logging, and pruning options are retired and rejected.
Remove any old root cron invocation before adopting this user-owned workflow;
do not run the wrapper with sudo. Existing system databases are left untouched.

DB-IP Lite data is licensed under **Creative Commons Attribution 4.0**; retain
attribution when using or redistributing it: [IP Geolocation by DB-IP](https://db-ip.com).
See the [DB-IP Lite download and license requirements](https://db-ip.com/db/lite.php).
Monthly MMDB files are not bundled with this repository or Python package.

### Normalized ban history

`offenders_events.py` parses complete timestamps, jail names, and compressed
IPv4/IPv6 addresses once, reading current, rotated, and gzip logs. Malformed
records are skipped. Events are sorted chronologically; equal timestamps retain
source encounter order without deduplication. Timestamps preserve fractional
seconds as naive local wall-clock values. Logs contain no UTC offset, so DST
ambiguity cannot be recovered.

`Report.events` is the selected history used for counts, rankings, and Last bans.
`Report.ban_lines` is only a derived raw-text compatibility view. Private,
loopback, and link-local filtering applies to rankings, not total/history counts.
The Last bans table retains its second-resolution display. Press `p` to cycle `1h -> 24h -> 7d -> 30d -> all -> 1h`.
The default `7d` is an exact rolling 168-hour window; `30d` is 720 hours.
Finite windows include both the exact lower boundary and the single captured
local report time, excluding future events. `all` includes every parsed event
available in the configured logs without time boundaries. Live jail status
remains independent of historical events.

### Structured Fail2Ban status and bounded commands

Each Fail2Ban status call has an eight-second timeout, closed standard input,
and uses an argument array without a shell. The reusable runner preserves exit
code, stdout, and stderr separately and distinguishes missing executable,
timeout, non-zero exit, and OS execution failure. Timeout retains partial output
and kills/reaps the direct child. A missing target behind sudo is reported as
sudo's non-zero exit, with its stderr retained.

`Report.jail_statuses` carries each jail's name, current/total failed and banned
counts, and normalized IPv4/IPv6 banned addresses in daemon jail order. Dashboard
ban rows retain their existing descending count order. Valid zero counts and empty
IP/jail lists remain successful data. Missing, duplicate, or malformed required
fields raise `Fail2BanParseError`; failed commands raise `Fail2BanCommandError`
with the original `CommandResult` and command arguments. Neither failure becomes
an authoritative empty list or zero count. The dashboard retains the last successful report on collection failure.

After each jail status, read-only `get <jail> bantime`, `get <jail> findtime`, and
`get <jail> maxretry` collect optional integer settings (times in seconds, including
negative bantime for permanent bans). Every call uses the same eight-second
bound. Unavailable settings are `None`; `setting_errors` retains command or parse
errors without discarding valid core status. Backend and filter identity remain
`None`: the 1.0.2 client contract exposes neither identity reliably. A file list,
journal match, or jail name is not a reliable substitute, and configuration files
are not scraped. The supported commands are documented in upstream's
[1.0.2 protocol](https://github.com/fail2ban/fail2ban/blob/1.0.2/fail2ban/protocol.py).
Other tools (GeoIP, WHOIS, and the updater) are outside this boundary.

### Avoid sudo password prompts

Because the app calls `sudo -n fail2ban-client ...`, you’ll typically want to allow passwordless access for `fail2ban-client` via `sudoers`.

The app never requests a sudo password; denied access fails immediately.

Edit safely with `visudo` and add something like:

```text
stef ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client
```

Adjust the username and path to `fail2ban-client` as needed:

```bash
which fail2ban-client
```

## Run

After pipx installation, run from any directory:

```bash
offenders
```

From the checkout, `python offenders.py` and `./offenders.py` also work with the
source installation virtual environment active. Run as the user with log-read and Fail2Ban permissions; the
application still invokes `sudo -n fail2ban-client` for jail status.

## Refresh behavior

Mount, the 30-second timer, manual refresh, GeoIP post-update refresh, and period
changes share one active report build.
Timer ticks during a build are skipped; pressing `r` displays “Refresh already
in progress” without cancelling or queuing work. The same applies to `p`.
Collection runs off the UI thread. A period change commits only after successful
recomputation; failure retains the prior period and tables. Other refreshes use
the committed period. Each build reads/parses logs once and selects events in memory.

A failed refresh preserves all tables and the last-success timestamp. The summary
shows the failure time, category, bounded detail, and that displayed data comes
from the last successful refresh, including its period. Before the first success, tables remain empty
and the summary explicitly says data is unavailable. The next successful refresh
replaces the report and clears the degraded state. Valid zero counts remain
successful data. There are no retries or queued refreshes.

## Key bindings

Global:

- `q` — quit
- `a` — open Coverage / Recommendations (manual, read-only analysis)
- `r` — refresh now
- `p` — cycle Period (first press from default `7d` requests `30d`)
- `t` — toggle table cursor mode (row/cell)
- `c` or `x` — copy selection
  - in **row** mode: copies the entire row (tab-separated)
  - in **cell** mode: copies the current cell

Dashboard summary:

- `v` cycles **IP → ASN → Country → IP**, only on the dashboard.
- IP retains the existing top-N ranking and `IGNORE_PRIVATE` policy.
- ASN/Country count all committed-period `Report.events`, including repeated bans,
  private/local addresses, and IPs outside top-N. Their totals can therefore exceed
  the visible IP-row total. Each row shows bans and distinct IPs.
- Mapped values, healthy **Unmapped**, and **Unavailable** are separate buckets;
  Country and ASN database outcomes are independent.
- Projection is lazy, local, and off the UI loop. It reuses structured top-offender
  enrichment and performs one local lookup per remaining unique IP. Both views
  share a snapshot until the next successful report; failures retain prior data.
- Aggregate rows support row/cell copy, but no IP inspector, WHOIS, or RDNS.
  **Last bans** remains independently IP-navigable and supports those tools.

Dashboard filter:

- `f` focuses the single-line Filter; typing immediately narrows **Top banned IPs**
  (or the active aggregate summary) and **Last bans** using a trimmed, case-insensitive literal substring.
- Search loaded IP, jail, Country, ASN (including `AS123`), and organization fields.
  Last bans reuse enrichment only for IPs already in Top banned IPs and remain
  limited to the loaded last ten events. Counts and row ordering are unchanged.
- `Enter` keeps the query and returns to the table; `Esc` clears it and returns.
  Deleting the text also restores all loaded rows. No matches is a safe empty state.
- The visible query survives successful refreshes and period changes; failures
  retain the last successful filtered rows. It is not saved between runs.
- Aggregate filtering only hides rows: matching one member IP, jail, Country,
  ASN, or organization shows the entire bucket with its full-period counts.
  It never filters events or recomputes counts, nor restarts a pending projection.
- Filtering performs no I/O or report rebuilds, even during collection. Live jail
  status and investigation screens retain their unfiltered full-period context.
  `f` is dashboard-only.

Jail detail:

- Focus **Active bans per jail**, move to a jail row, and press `Enter` to open it.
- `Esc` or `q` — return one screen, preserving the underlying navigation context.
- `r` and `p` remain available in detail. Successful refreshes update the open jail;
  failed refreshes retain its last successful status, history, and live IP snapshot.
- `e` — expand jail history from 10 to 50 to 100 to all-in-range events.
  Expansion survives successful refreshes and period changes; reopening starts at 10.

Jail counters/settings are **current live status**, not period-filtered totals.
History is filtered by the selected period and shown newest first. Current banned
IPs are a separate live Fail2Ban snapshot, independent of the historical period.
An active jail with no current IPs shows `(none)`; an inactive jail shows unavailable.
Opening, navigating, or expanding detail reuses the latest successful report and
performs no additional collection.

IP inspector:

- `Enter` on a real **Top banned IPs**, **Last bans**, or **jail history** row
  opens that normalized IP without collecting logs or querying Fail2Ban.
- The snapshot shows period ban count, first/last seen, distinct jails, per-jail
  counts, newest ten events, report timestamp, and independent Country/ASN states.
  Current ban membership and current jails are separate from period history.
  Healthy unmapped enrichment is distinct from unavailable enrichment.
- `Enter` on the inspector jail table opens historical or current jail detail.
  `Esc`/`q` backs out one screen to the same inspector or jail detail, retaining
  history expansion and table context. Dashboard return reselects the IP if present.
- Successful refreshes and global `p` period changes update the same selected IP
  in place, including when it disappears from history/current bans. Failed refreshes
  retain the last successful snapshot. Local projection runs off the UI thread.
- `c`/`x` retain the focused table's row/cell copy behavior.

Network tools (dashboard selected IP or inspector's fixed IP):

- `w` — WHOIS (requires `whois`)
- `d` — reverse DNS
  - runs `dig +short -x`; falls back to `getent hosts` only for command-not-found,
    never for timeout or non-zero exit

Both tools are explicit on-demand actions, run without sudo off the UI thread,
with an eight-second timeout per command and no retries. Output identifies the
command, stdout/stderr and failure category; rendered/copied text is capped at
approximately 200 KiB.

Modal popup (WHOIS/RDNS output):

- `esc` or `q` — close
- `c` — copy output (prints to stdout if clipboard isn't available)

## Configuration

Edit report settings in `offenders_report.py`:

- `TOP_COUNT` — number of offenders to show
- `IGNORE_PRIVATE` — skip private/loopback/link-local IPs

### Coverage / Recommendations

From the dashboard, press `a` to open one manual, read-only analysis snapshot.
`Esc` or `q` closes it; reopening starts a new snapshot. Analysis runs in a
background worker independently of the 30-second report refresh, `r`, period,
filter, view, and jail/IP navigation. It does not change dashboard report health.

The candidate table preserves policy order. Move between rows to read the
selected service/source, pattern counts, timestamp basis, coverage facts, up to
three literal examples, and all decision limitations:

- **Review existing disabled jail/filter** identifies a possible validation
  target. Its filter suitability is not established and it is not an instruction
  to enable the jail.
- **Review enabled jail/filter coverage** asks about substantial recurring
  evidence. It does not prove a jail failed or that a ban should already have
  happened: pre-ban failures, multiple clients, and ordinary timing/settings can
  explain visible records.
- **Investigate custom jail/filter candidate** identifies a supported gap for
  investigation. No configuration has been generated or regex validated; an
  existing suitable definition remains preferable if later found.

**No recommendation** is normal. Suppression counts explain below-threshold,
non-global-only, inactive, enabled-covered, and insufficient-evidence decisions.
Zero-pattern results summarize analyzed, unsupported, and unavailable/skipped/
partial source evidence. The UI never upgrades evidence beyond the #33 decision; partial positive
evidence can underpin a candidate, with all partial/truncated limitations retained. Local wall-clock and unknown timestamps cannot enforce
an exact UTC lookback. **Analysis unavailable** instead means the workflow failed.
Press `v` on a finding to open filter validation. Select one existing jail/filter
and explicitly press `v` or Enter to validate it. Merely opening or highlighting
a target does not run validation. `Esc` / `q` closes the validation screen.
Custom-gap `v` instead opens a dedicated custom-candidate screen. Press `v`
again to explicitly generate and validate a fixed template. Only Nginx/Apache
`sensitive_dotfile` and `path_traversal` signatures have custom templates.
Known stock authentication, database-admin/CGI and partially overlapping WordPress
patterns intentionally receive no generated duplicates: investigate/restore the
existing definition first.

Candidate filter and jail text appears only after the exact generated bytes pass
validation with every tested target line matched and zero missed/ignored lines.
Partial validation can remain reviewable with all limitations visible. Context is
not a known-clean corpus; context matches require review, and zero matches do not
prove low false-positive risk. Target matching never proves safety.

The candidate is read-only and starts `enabled = false`; local inherited ban
settings require operator review. Its jail wiring was not activated or
daemon-tested. `c` copies the displayed filter and jail snippets (or prints them
if clipboard support fails), but never writes the suggested files. Withheld
results show reasons/evidence without exposing or copying snippets.

Validation uses bounded local samples retained by the analysis and Fail2Ban's own
installed `fail2ban-regex`. It does not reacquire logs, perform DNS lookups, use
sudo, reload/enable jails, or write configuration. Target and same-source context
samples each contain at most 40 logical records and 64 KiB of UTF-8 text.
Displayed examples are limited to three per sample, 512 UTF-8 bytes each.
Match/miss/ignored counts describe **tested lines**, which can differ from logical
records for multiline text. Target matches show that the filter matched lines in
this bounded target sample; misses and ignored lines are concrete review evidence.
Context matches are not automatically false positives, and zero context matches
do not establish low false-positive risk. Successful validation does not establish
that a filter is safe or suitable for enabling. Samples may be partial; missing
context counts are unavailable, never assumed zero.

The existing-filter validation screen provides no configuration generation or mutation controls.

Edit `CHECK_INTERVAL_SECONDS` in `offenders.py` for the refresh interval.
Log paths are configured in `offenders_report.py`; GeoIP paths are owned by
`offenders_geoip.py`.

## License

MIT — see [LICENSE](LICENSE).

## Development tests

The application uses concrete modules with one-way imports:
`offenders.py` owns the dashboard and entrypoints, `offenders_report.py` selects
history and derives enriched reports, `offenders_events.py` acquires normalized
log events, and `offenders_fail2ban.py` owns bounded commands and status parsing.
The report imports events, Fail2Ban status, and `offenders_geoip.py` for enrichment.
`offenders_ip.py` projects a selected IP from normalized `Report.events` and
structured `JailStatus` address lists, keeping period history separate from current
ban membership. It reuses top-offender enrichment or performs one on-demand local
MMDB lookup; report-wide enrichment is unchanged. Its frozen snapshot includes
deterministic jail counts and the newest ten events. `offenders_ip_ui.py` owns
inspector rendering, asynchronous projection with stale-result protection, and
bounded WHOIS/RDNS output. Jail and IP screens use explicit callbacks for pushed
navigation without importing the app or each other.
`offenders_host.py` exposes an explicit read-only host exposure snapshot, separate
from ordinary report refresh. Local non-sudo `ss` supplies canonical endpoints;
optional process-owner and batch systemd evidence may be partial or unavailable.
Non-loopback bindings do not establish public Internet exposure. The snapshot
provides facts only, without coverage recommendations or log analysis.
`offenders_sources.py` consumes that supplied host snapshot explicitly and retains
its service states and health. It checks fixed standard file candidates using
metadata and direct readability only; missing, unreadable, unsupported, and
unavailable candidates remain distinct. Loaded systemd units receive one bounded,
non-sudo zero-line journal queryability probe, without reading history. Shared
sources retain all family associations; unknown listeners stay unassociated.
Source discovery has no UI, persistent cache, or report-refresh hook.
`offenders_coverage.py` consumes one supplied source snapshot, retaining the exact
upstream evidence without reacquiring host/source state. Running jails come from
`get_jail_list()`; concrete file/journal facts use Fail2Ban 1.0.2's read-only
`get <jail> logpath` and `journalmatch`, through the same eight-second sudo boundary.
Custom jail names are preserved; names alone never establish running coverage.
Static jail configuration follows `jail.conf`, lexical `jail.d/*.conf`,
`jail.local`, lexical `jail.d/*.local` precedence. Direct filter `.conf`/`.local`
files establish definition existence and literal journal units. Reads use the
current user, confined to `/etc/fail2ban`, with 256-file, 1-MiB-per-file and
8-MiB-total bounds. Raw INI parsing does not reproduce general interpolation or
include chains; unsupported, unreadable, or oversized evidence stays partial.
Any unresolved jail include blocks static disabled candidates because its
enabled, filter, or source overrides are unknown; concrete runtime coverage
remains authoritative.
Source-family targets distinguish `covered_enabled`, `available_disabled`,
`no_obvious_match`, and `insufficient_evidence`. An exact stock-family catalog
can establish disabled-definition relevance, explicitly without proving a
concrete source relationship. These are facts, not recommendations. Generic
listeners and observed services without sources remain insufficient evidence.
Coverage is explicitly invoked and stays outside report/dashboard refresh,
filtering, and navigation.
`offenders_evidence.EvidenceCollector.collect(source_inventory, force=False,
lookback=timedelta(hours=24))` explicitly consumes one supplied #28 snapshot.
It never rediscovers host/source/coverage state or runs on dashboard refresh.
One in-process cache entry retains successful or partial snapshots for five
monotonic minutes, keyed by inventory object identity and lookback; force bypasses
it. Lookback must be a positive timedelta no greater than seven days.
File evidence uses the resolved target, bounded 256-KiB tails from current and one
plain `.1` rotation, at most 2,000 lines/512 KiB per source. All current sources
precede rotations. Compressed history is not read. File timestamps stay unset;
#31 owns source-specific timestamp interpretation and security-pattern semantics.
Journal evidence uses one non-sudo, eight-second JSON query through #14 per readable
unit, with the captured UTC lower bound and newest 1,000 entries (4-MiB parse cap).
The runner still captures stdout before returning; this is a parse/retention cap,
not a streaming subprocess-memory guarantee. Stable device/inode/byte offsets and
journal cursors drive exact deduplication with unioned source identities. Equal
text alone never deduplicates. Snapshots retain exact upstream associations,
per-source record ordering, and explicit skipped/unavailable/partial/truncated
outcomes. Global retention stops at 10,000 records or 8 MiB of UTF-8 text, with
16 KiB per record. File line bodies preserve CR and other raw characters but omit
the LF delimiter. No unified file/journal event chronology is inferred.
`offenders_patterns.analyze_patterns(evidence_snapshot)` consumes that exact #30
snapshot in memory, retaining it in a frozen pattern inventory without acquisition
or dashboard integration. Its small explicit format catalog recognizes SSH,
Dovecot, vsftpd, ProFTPD, and English Pure-FTPd authentication failures, plus
Nginx/Apache HTTP-auth failures and specific rejected path-probe categories.
Caddy is explicitly unsupported. Ordinary unrelated 404s, successful HTTP access,
and unrecognized lines are ignored; this is not general anomaly detection.
Only supplied source-family associations authorize recognition. Groups use stable
semantic signatures and canonical source scopes: resolved-file aliases collapse,
while journal units and file/journal backends remain separate. Counts measure
recognized log records, not unique sessions. IPv4-mapped IPv6 normalizes to IPv4;
distinct global/non-global IP counts use `ipaddress.is_global` without judgments
about trust or maliciousness. One-event groups remain available to #33, which owns
recurrence thresholds, coverage correlation, and finding decisions.
Structured journal and explicit-offset file times use UTC; aware events outside
the supplied interval are excluded. Local file times remain naive wall-clock
values, with only the year inferred for RFC3164, and cannot enforce the UTC window.
Missing/malformed event times remain unknown; file mtime and collection time are
never substituted. Each time basis groups separately. Source-family analyses
retain partial/truncated/unavailable/skipped evidence and distinguish ignored
records from recognized records excluded by the UTC window. Output ordering uses
source/family/signature/time basis and backend record identities, not text hashes.
Groups keep at most three examples of 512 UTF-8 bytes each; source/group/event
limitations retain at most 32 details of 300 bytes each, marking caps explicitly.
`offenders_findings.build_findings(pattern_inventory, coverage_inventory)` purely
joins #31 patterns and #29 coverage retaining the exact same #28 source inventory
object; separately acquired snapshots raise `ValueError`. Resolved file aliases
join once per canonical source/family. Known active service states, at least
three recognized records, and at least one global source IP gate candidates.
Exact pattern/filter compatibility narrows family/source coverage; source
monitoring alone does not prove event/filter matching. Compatible enabled jails
suppress ordinary candidates; only at least 10 records from two global IPs or
20 records from one global IP produce an enabled tuning question. Unknown running
filter relevance blocks disabled/custom candidates. Disabled definitions remain
validation targets, and custom gaps require an explicit complete-enough coverage
negative. Partial positive history can qualify with its limitations retained.
Every group receives one frozen candidate, suppression, or insufficient-evidence
decision with its original group and contributing coverage facts. Findings are a
subset of those decisions, with no scores, UI, regex validation, or mutation.
`offenders_recommendations_ui` owns only the manual workflow and presentation.
Opening its screen runs host -> sources -> coverage -> evidence -> patterns ->
findings in one background worker, sharing the exact source inventory between
coverage and evidence. Policy remains in #33 (`offenders_findings`). There is no automatic or persistent analysis, report
refresh hook, or second evidence cache. Closing cancels result delivery; bounded
underlying reads may finish afterward.

`offenders_validation` accepts only exact finding/target objects from the supplied
inventory. It uses the retained group's record identities for the target and the
canonical source/family analysis's alias keys for same-source context records.
Missing target identities fail closed. Each operation owns a secure temporary
directory and mode-0600 sample files, cleaned after success, failure, or timeout.
The optional `config_root` argument is a test seam; production uses `/etc/fail2ban`.
Safe literal `filter[options]` arguments and `%(__name__)s` substitution preserve
known effective options. Complex/unresolved options fall back to the resolved
base stem with an explicit partial limitation.

Each non-empty target/context pass calls #14 `run_host_command` once with
`fail2ban-regex --usedns=no --encoding=utf-8 --print-no-missed --print-no-ignored
-c /etc/fail2ban -- <sample> <filter>`, `sudo=False`, and an eight-second timeout.
There is no shell or retry. Only the stable Fail2Ban 1.0.2 summary
`Lines: N lines, I ignored, M matched, X missed` is parsed: exactly one summary,
nonnegative integers, and `I + M + X == N` are required. Zero matches are valid
execution evidence. Parsing examines the newest 256 KiB of stdout and retains
only counts and up to 300 UTF-8 bytes of error detail. This is a **post-run parse
and retention cap**, not a streaming process-memory bound: #14 first captures
the process output. Full stdout/stderr are not retained in validation results.

The custom-text validation API requires an exact custom
gap candidate, valid UTF-8 text at most 64 KiB without NUL, a non-empty
`[Definition]` / `failregex`, and only optional `[Init]`. Include chains, defaults,
and filesystem-path inputs are rejected. Text is written to a private temporary
`.conf`; its exact SHA-256 and byte count identify what was tested, without a
trust score. The custom-candidate screen supplies fixed text; it has no editor.
`offenders_validation_ui` owns an explicit single-target worker and renders
complete/partial/unavailable evidence separately from the unchanged #33 graph.
Closing discards delivery while the backend completes bounded execution/cleanup.
`offenders_candidate` owns the fixed four-signature template catalog, exact retained
custom-gap decision identity, collision checks against retained static inventory,
and conservative source wiring. It never mines regexes from logs or recomputes
finding policy. File wiring preserves one exact configured absolute identity,
not its resolved alias; multiple aliases or unsafe INI/path syntax are withheld.
Journal wiring requires one canonical safe unit, exact filter `journalmatch`,
and jail `backend = systemd` without a logpath. Both use web ports and `usedns = no`.
Ban policy inherits local defaults; no timing, retry or action policy is generated.

The exact UTF-8 filter bytes go through `validate_custom`; decision identity,
target kind, SHA-256 and byte count must agree. Only complete/partial validation
with positive tested target counts, every tested line matched and zero missed or
ignored lines exposes either snippet. Context never controls that gate. Withheld
results retain validation evidence but no filter/jail text.
`offenders_candidate_ui` owns explicit off-loop generation, suppresses concurrent
work and stale delivery, renders literal text and exposes copy only for the
displayed reviewable result. Coverage retains its original inventory and routes
existing findings to `ValidationScreen` unchanged.

No production-host validation is claimed by the offline fixtures.

Source execution requires the packaged `offenders*.py` modules together.

Code Guard uses its normal policy without a large-file exemption: 600 counted
LOC is the hard gate and files above 400 counted LOC require cohesion review.

After installing the project in your virtual environment, run:

```bash
python -m unittest discover -s tests -v
```

The suite uses Python's standard-library `unittest`, temporary log files, and
local Fail2Ban status fixtures. Running it requires no daemon, root access,
network access, or GeoIP databases. It covers ban recognition, IP normalization
and local-address filtering, numeric gzip rotation ordering, exact rolling
period boundaries (`all` includes all parsed events), and jail/table parsing.

The suite also mounts the real Textual dashboard with a fixture report, checks
table rendering and cursor-mode switching, and quits through the keyboard binding.
It does not require a running Fail2Ban daemon.

### Runtime qualification

Fresh installation and the offline suite were validated on Ubuntu 24.04 with
Python 3.12.3 and Textual 8.2.8, with the base dependencies. Both the
installed command and executable source script rendered and exited successfully
in a local pseudo-terminal without a live Fail2Ban daemon.
Existing UI compatibility fallbacks remain because the parsing tests from #12
do not protect those UI paths.

Read-only production inspection on 2026-09-27 confirmed Ubuntu 24.04.5,
Python 3.12.3, and Fail2Ban 1.0.2, eight active jails, readable Fail2Ban logs,
and zero current bans in the inspected `sshd` jail. Status inspection required
`sudo`; no server files, packages, configuration, or Fail2Ban state were changed.

Offenders uses `fail2ban-client status`, `status <jail>`, and the three read-only
`get <jail>` settings commands documented above. These commands and status fields
are supported on the compatibility floor; no Offenders dependency requires Fail2Ban 1.1.x. Tests use
captured 1.0.2 status output plus representative 1.0.x/1.1.x output with nonzero
ban counts. See [fixture provenance](tests/fixtures/README.md).

Qualification combines the local smoke test of the new application revision,
read-only production inspection, and offline parsing tests. The new revision was
not installed or launched on production, and no live 1.1.x daemon was exercised.
This evidence does not claim end-to-end execution of the new revision on the server;
a server upgrade or installation is not required for this compatibility assessment.
