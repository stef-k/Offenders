# Developer appendix

Preserved developer notes; architecture and maintainer documentation revision is
tracked separately. See the [operator documentation](docs/README.md) for usage.

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
`get <jail>` settings commands documented in the
[operator permissions guide](docs/installation.md). These commands and status fields
are supported on the compatibility floor; no Offenders dependency requires Fail2Ban 1.1.x. Tests use
captured 1.0.2 status output plus representative 1.0.x/1.1.x output with nonzero
ban counts. See [fixture provenance](tests/fixtures/README.md).

Qualification combines the local smoke test of the new application revision,
read-only production inspection, and offline parsing tests. The new revision was
not installed or launched on production, and no live 1.1.x daemon was exercised.
This evidence does not claim end-to-end execution of the new revision on the server;
a server upgrade or installation is not required for this compatibility assessment.
