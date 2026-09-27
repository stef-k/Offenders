# Offenders (Fail2Ban TUI)

Offenders is a Linux terminal dashboard for Fail2Ban history and live jail status.
Inspect banned IPs, ASN/Country summaries, jail settings and current membership;
run on-demand WHOIS/RDNS lookups or a manual Coverage analysis for review.

Reports and investigation are read-only with respect to Fail2Ban configuration
and bans. There is no ban/unban action. Coverage, validation, and custom candidates
never install filters/jails or enable/reload Fail2Ban. The only persistent
application-owned changes are explicit or opt-in GeoIP data/policy updates in
your user data directory; validation also uses temporary local sample files.

[Install](#install-and-upgrade) · [Controls](#key-and-action-map) ·
[GeoIP](#optional-geoip-enrichment) · [Troubleshooting](#troubleshooting)

## Screenshot

![Offenders TUI screenshot](offenders-screenshot.jpg)

## Requirements and permissions

The supported baseline is **Ubuntu 24.04 LTS / Python 3.12+**, with separately
installed **Fail2Ban >=1.0.2**. Python dependencies are
`textual>=8.2.8,<9` and `maxminddb>=3.1,<4`; package installation supplies these.

The dashboard needs Fail2Ban file logs and permission to read them. Defaults are
`/var/log/fail2ban.log`, its `.1` rotation, and `.N.gz` rotations. Journal-only
Fail2Ban logging does not supply the ordinary report history.

Live jail/status/settings calls use **`sudo -n fail2ban-client`**, with an
eight-second limit per call. Offenders never waits for a sudo password. Denied
commands are failures, not authoritative zero counts. Run the dashboard as your
normal user with the required log access and narrowly scoped sudo permission.

An administrator can use `visudo` to permit only the read commands below. Replace
`OPERATOR` with the login name and verify the installed executable path with
`command -v fail2ban-client` before adapting this example:

```sudoers
OPERATOR ALL=(root) NOPASSWD: /usr/bin/fail2ban-client status, /usr/bin/fail2ban-client status *, /usr/bin/fail2ban-client get * bantime, /usr/bin/fail2ban-client get * findtime, /usr/bin/fail2ban-client get * maxretry, /usr/bin/fail2ban-client get * logpath, /usr/bin/fail2ban-client get * journalmatch
```

The status and first three `get` forms serve the dashboard; `logpath` and
`journalmatch` serve optional Coverage. An administrator can further restrict
wildcard jail arguments to the actual jail names. Do not grant unrestricted
passwordless `fail2ban-client` access: it also exposes mutation commands.

Coverage can degrade independently of the ordinary dashboard:

| Evidence/action | Command or access | If unavailable |
| --- | --- | --- |
| Listener discovery | Non-sudo `ss -H -lntu` | Exposure evidence unavailable |
| Optional process owners | Bounded `sudo -n ss -H -lntup` | Owner evidence partial/unavailable |
| Systemd/source discovery | Non-sudo `systemctl` / `journalctl` | Service/journal evidence partial/unavailable |
| Static configuration | Read `/etc/fail2ban` as the current user | Coverage cannot imply complete configuration access |
| Source log evidence | Read discovered logs as the current user | Source evidence partial/unavailable |
| Explicit filter validation | Installed `fail2ban-regex`, without sudo | Validation unavailable |

Owner enrichment is optional; it does not require broad sudo permission. If an
administrator chooses to allow it, limit permission to the exact `ss` invocation
above and verify that executable's path separately.

WHOIS requires optional `whois`. RDNS uses optional `dig +short -x` and falls back
to `getent hosts` **only when dig is missing**, never after a timeout or nonzero
exit. On Ubuntu these optional tools can be installed with
`sudo apt-get install whois dnsutils`. They are not needed for the dashboard.

## Install and upgrade

**The first PyPI publication is pending.** The intended distribution name is
`offenders`; registration acceptance and OIDC publication are not yet proven.
The following index commands become usable after publication. Until then use
the secondary source workflow or a locally built wheel described in
[release preparation](RELEASING.md).

After publication, pipx/PyPI is the primary Linux application path:

```bash
sudo apt-get update
sudo apt-get install -y pipx
pipx ensurepath
# Open a new login shell after ensurepath, then:
pipx install offenders
command -v offenders
offenders
```

Upgrade or remove the package with:

```bash
pipx upgrade offenders
pipx uninstall offenders
```

pipx isolates Python dependencies; it does not install Fail2Ban or host tools or
grant log/sudo permissions. Installation downloads no GeoIP data. Uninstalling
the package does not delete user-owned XDG GeoIP data.

### Migrating from a standalone installation

Migration is additive. Record the old executable path and preserve its files and
Python environment for rollback. Use `command -v offenders` (and Bash's
`type -a offenders`) before and after installation to detect command shadowing.
Check the executable location reported by pipx; deliberately select it through
PATH or its full path when ready to verify `offenders geoip status` and launch.
Keep the same user/XDG environment to retain GeoIP data and policy. Rollback
means restoring the old command resolution and environment; retain the old
installation until the replacement is verified. These are migration guidelines,
not evidence of a production cutover or an instruction to perform one now.

### Source and advanced installs

From a checkout, with `python3-venv` available:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
offenders
```

`python -m pip install .` provides a non-editable source install;
`pipx install .` provides local application isolation. With the source environment
active, `python offenders.py` or `./offenders.py` also launches the dashboard.
Keep the packaged modules together: copying only the old single script is not a
current installation method. See [development tests](#development-tests) for
contributor guidance and [release preparation](RELEASING.md) for local wheel checks.

## Run and CLI

Run `offenders` from any directory after installation, as the user with the
permissions above. The supported application forms are:

```bash
offenders                       # dashboard
offenders geoip status          # read-only local health and policy
offenders geoip update          # explicit download and activation
offenders geoip auto on         # persist opt-in for future launches
offenders geoip auto off        # persist disabled policy (the default)
```

Status, local reads, imports, and lookups never download. Manual update performs
network access and writes user-owned data. Automatic policy is off by default;
changing it persists local state. The normal 30-second report refresh never
checks for GeoIP updates. There are no top-level `--help`, `--version`, or generic
configuration commands.

## Optional GeoIP enrichment

Offenders works without GeoIP databases. Country and ASN have independent health
and source selection. **Unmapped** means a healthy database has no mapping for
that IP; **Unavailable** means usable enrichment could not be obtained. Neither
means there were no ban events.

Preferred storage is `$XDG_DATA_HOME/offenders/geoip`, or
`~/.local/share/offenders/geoip` when unset. Use the same user and XDG environment
for the CLI and dashboard. Existing flat files there remain readable. Legacy
`/usr/share/GeoIP/dbip-{country,asn}-lite.mmdb` files are read-only fallback,
selected independently when preferred Country or ASN data is missing/unhealthy.
Updates never modify those system files.

The first explicit update is consent to download DB-IP Lite Country and ASN data
into user-owned storage. Updates validate both files before activation; failed
acquisition preserves usable active data. Successful activation becomes visible
without restarting through normal report refresh. A dashboard update requests a
refresh; if collection is already running, the next normal refresh picks it up.
Diagnostics show update errors separately from report health.

Automatic updates require opt-in. Enabling the policy takes effect at the next
dashboard launch: one check runs after mount, subject to a 24-hour check interval.
An already activated current UTC month is not downloaded again automatically;
a previous-month publication fallback can retry after 24 hours. Manual updates
are explicit and run regardless of that automatic schedule.

Diagnostics show each source, reader health, path, local age, policy, and latest
outcome. Files older than **62 local days** produce a stale warning, not invalidity;
readable data remains usable. Healthy fallback and healthy-but-unmapped addresses
do not cause the global unavailable/stale warning.

No root cron job, `mmdblookup`, `geoip2`, network GeoIP lookup API, or bundled monthly
dataset is needed. If migrating an old updater, retire its root cron invocation;
old system-target/updater flags are no longer supported. The compatibility wrapper
`update_geoip_db.py` is rootless and is not the normal installed command.

DB-IP Lite is licensed under **Creative Commons Attribution 4.0**. Retain
[IP Geolocation by DB-IP](https://db-ip.com) attribution when using or redistributing
it; see the [DB-IP Lite license requirements](https://db-ip.com/db/lite.php).

## Dashboard, history, and refresh

The default period is **7d**. Choices cycle
`1h -> 24h -> 7d -> 30d -> all -> 1h`. Finite periods are rolling local-time windows
(7d is 168 hours; 30d is 720), from the lower boundary through the report time.
`all` uses every parsed event in available logs, without time boundaries.
Current and rotated logs, including gzip history, contribute events; malformed
records are skipped. Source timestamps without offsets remain local wall-clock
values: timezone/DST ambiguity cannot be recovered. Tables display seconds.

Historical counts and Last bans describe the committed period; current jail
counters and banned addresses describe the live Fail2Ban snapshot. Top IPs can
exclude private, loopback, and link-local addresses. ASN/Country summaries count
all committed-period events, including repeated bans and private/local addresses
outside the Top IP ranking. Aggregate rows show ban and distinct-IP counts with
separate mapped, Unmapped, and Unavailable buckets. Their totals can exceed the
visible Top IP total. Last bans displays the newest ten events.

Startup, the 30-second timer, manual refresh, period changes, and post-update
refresh share **one active report build**. Requests during a build do not cancel
or queue work; manual refresh/period requests report that refresh is in progress.
A period change commits only on success. Failure retains last-known-good tables,
period, and timestamp with a degraded message; before the first success, data is
explicitly unavailable. A successful recovery replaces the data and clears the
warning. Valid zero counts are successful data.

Filtering is display-only, in memory, and never reruns collection. A trimmed,
case-insensitive literal query matches loaded IP/jail/Country/ASN/organization
fields in the summary and Last bans. Last bans enrichment is limited to IPs
already in Top IPs. Aggregate matching shows a whole bucket with its full counts,
not just matching events. The query survives refresh/period changes but not a
restart. Live jail status and investigation retain their unfiltered context.

## Key and action map

Keys are contextual: focused text input handles typing, and screen-local actions
take precedence over dashboard bindings. The map below describes supported
contexts rather than promising every app binding on every modal.

| Context | Key/action | Result |
| --- | --- | --- |
| Dashboard | `q` | Quit |
| Dashboard; jail/IP detail | `r` / `p` | Refresh / request next period, sharing the single-build gate |
| Dashboard | `f` | Focus filter; Enter keeps query and returns to table; Esc clears and returns |
| Dashboard | `v` | Cycle IP / ASN / Country summary |
| Dashboard | `a` | Open one Coverage analysis snapshot |
| Dashboard | `g` | Open GeoIP diagnostics |
| Dashboard tables; jail/IP detail tables | `c` / `x` | Copy focused row (tab-separated) or cell, according to cursor mode |
| Dashboard tables; jail/IP detail tables | `t` | Toggle focused table row/cell cursor mode |
| Dashboard real Top IP or Last bans row | Enter | Open IP inspector |
| Dashboard Active bans per jail row | Enter | Open jail detail |
| Dashboard real Top IP or Last bans row; IP inspector | `w` / `d` | Explicit WHOIS / RDNS for the selected/fixed IP |
| GeoIP diagnostics | `u` / `a` | Update now / persist automatic-policy toggle |
| GeoIP diagnostics | Esc / `q` | Close |
| Jail detail | `e` | Expand history 10 → 50 → 100 → all in period; stays at all |
| Jail history real-IP row | Enter | Open IP inspector |
| IP inspector jail row | Enter | Open jail detail |
| Jail detail; IP inspector | Esc / `q` | Back one screen |
| Command output | `c` | Copy rendered output |
| Command output | Esc / `q` | Close |
| Coverage finding | `v` | Open existing-filter validation or custom-candidate screen |
| Existing-filter validation | `v` / Enter on target | Explicitly validate selected target |
| Custom candidate | `v` | Explicitly generate and validate a fixed template |
| Custom candidate | `c` | Copy only an exposed reviewable result |
| Coverage; validation; custom candidate | Esc / `q` | Close |

Aggregate rows support row/cell copying but do not represent one IP: no IP
inspector or WHOIS/RDNS is available from them. Last bans remains IP-navigable.
Copy actions use terminal clipboard support, with stdout fallback on a reported
clipboard exception. Command-output `c` copies output, not a table selection.

## Jail and IP investigation

Open a jail from Active bans per jail. Counters and available bantime/findtime/
maxretry settings are live values, independent of period history. Unavailable
settings are not zero; backend/filter identity may be unavailable. Current banned
IPs are separate from historical bans: `(none)` means a valid empty current list,
while an inactive jail has unavailable current membership.

Jail history is newest first and expands within the selected period. Opening or
expanding detail reuses the last successful report without extra collection.
Expansion survives refresh and period changes; reopening starts at ten.

Open an IP from a real Top IP, Last bans, or jail-history row. Its inspector shows
period ban count, first/last seen, distinct jails, per-jail counts, newest ten
events, report timestamp, and independent Country/ASN states. Current membership
is separate from period history. Enter on an inspector jail opens its detail;
back navigation preserves the underlying jail/IP context and history expansion.
Returning to the dashboard reselects the IP when present.

Successful refresh/period changes update open jail/IP views in place, even if the
selected IP disappears from history or current bans. Failures retain the last
successful snapshot. WHOIS/RDNS are explicit on-demand network tools, never
background enrichment. Commands run without sudo with eight-second timeouts and
no retries; output shows command, stdout/stderr, and failure category. Displayed
and copied output is capped at approximately 200 KiB.

## Coverage, recommendations, and validation

Opening Coverage starts one explicit background analysis snapshot. Reopening
starts a new analysis; recently collected evidence may be reused. Normal dashboard
refresh never runs it. Analysis is independent of report health and may be partial
or unavailable because listeners, owners, journals, configuration, or logs cannot
be read. Read the source limitations alongside every result.

Host bindings do **not** establish Internet reachability. Source coverage does
not establish maliciousness, filter suitability, or that a ban should already
exist. Pattern recognition uses a fixed supported catalog of authentication
failures and specific web probes, not generic anomaly detection. Unsupported
formats remain unsupported. File evidence uses bounded current/plain-rotation
tails; Coverage does not read compressed history, unlike ordinary ban reports.
Local/unknown timestamps cannot establish an exact UTC lookback.

Recommendations ask you to review an existing disabled definition, review enabled
coverage, or investigate a supported custom gap. They are not instructions to
enable a jail. No recommendation is a normal result; suppression and evidence
summaries explain limitations. Analysis unavailable instead indicates failure.

Existing-filter validation requires explicit target selection and execution;
opening/highlighting alone does not validate. It uses bounded retained target and
same-source context samples with installed `fail2ban-regex`, without sudo or DNS
lookups. It does not reacquire logs or change configuration. Counts describe tested
lines, which may differ from logical records. Success means the tested sample
matched, **never that a filter is safe**. Context is not a known-clean corpus:
context matches need review and zero matches do not prove low false-positive risk.
Missing context evidence is unavailable, not zero.

Custom generation supports only fixed Nginx/Apache sensitive-dotfile and
path-traversal gaps. It does not generate generic regexes or duplicate known stock
authentication patterns. Filter/jail snippets are exposed only when their exact
filter text validates with all tested target lines matched and none missed/ignored.
Partial results retain their limitations. Withheld results cannot be copied.

Candidates start `enabled = false`, inherit local ban policy for operator review,
and are copy-only. Wiring has not been activated or daemon-tested. Offenders never
writes suggested configuration files, installs/enables/reloads jails, or bans or
unbans an IP. Review evidence and local policy independently before any manual use.

## Configuration

There is no generic user configuration file. Periods are fixed runtime choices;
GeoIP data and automatic policy are user-owned XDG state.

For deliberately maintained **source builds**, advanced constants are:

- `TOP_COUNT` and `IGNORE_PRIVATE` in [offenders_report.py](offenders_report.py):
  Top IP ranking size and exclusion of private/loopback/link-local addresses.
- `LOG_CURRENT`, `LOG_ROTATED`, and `LOG_GZ_GLOB` in that file: report log paths.
- `CHECK_INTERVAL_SECONDS` in [offenders.py](offenders.py): report refresh interval.

These are source edits, not settings exposed to normal pipx users. Editable
installation keeps source changes effective; package upgrades replace installed
code. Do not confuse ranking exclusions with full-period aggregate/history counts.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| Fail2Ban command denied/unavailable, timeout, or parse failure | Read the degraded detail; verify Fail2Ban availability, actual client path, and narrowly scoped noninteractive sudo permission. Last-good data is retained; it is not current success. |
| Missing or unreadable report history | Verify configured file paths and current-user read access, including rotations. Missing files are skipped, so no history does not prove there were no bans; unreadable files can fail collection. |
| GeoIP unavailable or reader failure | Inspect diagnostics/status for independent Country/ASN sources and reader errors; check the same user/XDG environment and file readability. Unmapped is a different state. |
| GeoIP stale | Local age exceeds 62 days; readable data remains usable. Choose an explicit update if desired. |
| GeoIP update failure | Read the latest outcome; usable active data is preserved. Check the reported network/storage/validation error before choosing another explicit attempt. |
| WHOIS/RDNS unavailable | Check the named optional tool and command failure; RDNS falls back to getent only when dig is missing. |
| Coverage partial/unavailable | Read source limitations for owner/journal/config/log access. Optional evidence failure is not proof of no exposure or complete protection. |
| Unexpected old dashboard or unrecognized GeoIP command | Use `command -v offenders` and Bash `type -a offenders` to check whether the retained standalone executable shadows pipx. |

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
