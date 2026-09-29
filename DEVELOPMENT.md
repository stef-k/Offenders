# Development and architecture

This is the maintainer reference for the current codebase. User workflows belong
in the [operator documentation](docs/README.md).

## Development setup

The contributor baseline is Ubuntu 24.04 with Python 3.12. From a clean checkout:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
```

Use the local virtual environment, without root or changes to system Python.
`pyproject.toml` owns dependency, version, and package metadata;
`requirements.txt` is compatibility shorthand pointing at the project. Initial
installation needs access to dependencies (an index or a local cache). Ordinary
offline development and tests need no network, live Fail2Ban, or GeoIP databases.
Release tools such as `build`, `twine`, and `actionlint` are separate contributor
tools, not runtime dependencies.

## Architecture overview

Concrete modules separate acquisition, projections, policy, and Textual screens.
The dashboard consumes reports; the manual Coverage workflow consumes its own
explicit inventory. Neither workflow silently starts the other.

| Responsibility | Modules |
| --- | --- |
| Entrypoint, dashboard composition, global routing, report scheduling | `offenders.py` |
| Report model, period selection, top-offender enrichment | `offenders_report.py` |
| Normalized ban history from current, rotated, and gzip logs | `offenders_events.py` |
| Bounded commands, Fail2Ban status/settings/source-query parsing | `offenders_fail2ban.py` |
| In-memory display filtering | `offenders_filter.py` |
| Aggregate projections and presentation | `offenders_aggregate.py`, `offenders_summary_ui.py` |
| Jail history and current-ban details | `offenders_jail_ui.py` |
| Report-derived IP projection, inspector, Registration/RDNS UI | `offenders_ip.py`, `offenders_ip_ui.py` |
| Explicit PTR/RDAP acquisition, normalized outcomes, bounded literal text | `offenders_lookup.py` |

## Dashboard and report path

A report combines selected historical ban events with independently acquired
current jail status. Period selection filters parsed history; `all` includes all
available parsed events. Current ban membership is not a historical event count.
Top-offender enrichment uses local GeoIP readers.

`OffendersApp` schedules a single report worker at a time. A successful result
becomes the committed report and period; transient collection or parsing failures
leave the last-known-good tables intact and surface degraded status. Before any
successful report, failures show an unavailable state. Cancellation and worker
identity checks prevent stale completions from committing.

Filtering, jail/IP navigation, and aggregate views reuse the committed report
instead of rediscovering host state. IP/aggregate projections may perform local
GeoIP lookups for addresses outside the enriched top list. Report collection,
those projections, and explicit Registration/RDNS Python network work run off the Textual
event loop. Screens reject stale deliveries after replacement or closure.
Navigation callbacks keep jail and IP screens independent of app imports.
`offenders_lookup` directly depends on `dnspython` and classic `ipwhois`; pipx
installs both. PTR uses the host-configured resolver with a finite lifetime and no
NSS fallback. Registration preflights global unicast addresses and uses shallow,
zero-retry RDAP with bootstrap enabled, without ASN/NIR/entity follow-ups. RDAP's
finite transport timeout does not imply a total deadline across redirects, and
its public transport errors intentionally share `rdap-unavailable`. Provider seams
are mocked in ordinary tests; no DNS/RDAP requests run during them. The generic
host-command runner remains owned by Fail2Ban/host acquisition.
See [usage](docs/usage.md) for operator controls and outcome categories.

## Background activity convention

`offenders_activity.ActivityWorkers` is the application's single Textual worker
manager. Every `@textual.work` and `node.run_worker` operation automatically
participates, including thread and coroutine workers on widgets, screens, and
the App. Use these APIs for slow work; do not bypass them with raw threads,
executors, or detached asyncio tasks. Timer callbacks schedule through the same
APIs. Immediate local event handlers do not register activity.

A worker may use `name="activity:Human label…"`, or the UI thread may call
`app.workers.label(worker, "Human label…")` for a dynamic target. Unlabelled work
shows `Working…`; argument-bearing worker descriptions are never displayed.
Worker identities preserve overlapping operations. No manual start/stop pairing
is required. Screen-local detailed feedback remains with its existing owner.
`OffendersFooter` combines the native Textual `Footer` (binding visibility,
clicks, and horizontal scrolling) with a right-aligned literal `ActivityStatus`.
Every product screen composes `OffendersFooter` explicitly; framework and
non-product screens retain their native layout. Command-output modals use the
same footer. Its height stays one row; the activity label is ellipsized at 45% of
available width so bindings retain space on narrow terminals. The old separate top row is removed.

The manager retains one shared presentation deadline using a monotonic clock and
an app-owned Textual timer. The first activity in a continuous visible interval
starts a 500 ms minimum hold. Further workers update that presentation without
restarting the deadline; overlap shows a primary label plus `(+N)`. When no work
remains, only clearing the label waits for the deadline. Results, cancellation,
navigation, and single-flight eligibility never wait. New screens inherit the
held label. After the deadline, any remaining work stays visible until completion.
The hold acknowledges recently accepted work, not an additional worker lifetime.
Lookup wording remains in the lookup UI, so backend changes can update both the
local and shared label together.

Textual 8 worker state messages do not bubble and cancellation before execution
may omit a terminal message. The small compatibility seam installs `App._workers`
and overrides `WorkerManager._remove_worker` for task-done cleanup. Registration
updates presentation synchronously before execution; completion removes only its
own activity, including error and pre-start cancellation. Deferred workers become
active through `start_all`. Keep lifecycle tests green on Textual upgrades.
Dismissed screen workers are cancelled by Textual; existing cancellation and
stale-result guards still protect delivery. Cancellation releases actual activity immediately; the visual hold may remain but
does not forcibly terminate bounded backend threads or replace backend locks.
GeoIP's app-lifetime owner continues updating after diagnostics closes.

The current asynchronous audit covers all ten worker paths:

| Trigger | Worker / feedback |
| --- | --- |
| Initial report, timer, refresh, period, GeoIP activation | `_collect_report`: refreshing or pending period |
| GeoIP mount / opted-in startup update | `_startup`: checking, then updating |
| GeoIP Update now | `update_now`: updating |
| GeoIP automatic-policy toggle | `toggle_auto`: saving policy |
| Explicit Registration / RDNS | `CommandOutputModal._run`: provider-specific working text |
| IP mount / successful new report | `IPInspectorScreen._project`: loading details |
| Coverage mount | `_analyze`: analyzing coverage |
| Selected filter validation | `_validate`: validating |
| Custom template action | `_generate`: generating and validating |
| ASN/Country selection / successful new report | `DashboardSummary._project`: loading summary |

Filtering, copy, cursor movement, jail-history expansion, back navigation, and
ordinary snapshot rendering remain immediate/local. Mount/navigation that starts
one of the workers above inherits activity automatically. Duplicate report,
GeoIP, validation, and candidate actions retain their single-flight rejection
feedback. `tests/test_activity.py` audits runtime scheduling for unmanaged work
and proves generic participation; existing product tests cover detailed states.

## GeoIP lifecycle

| Responsibility | Module |
| --- | --- |
| Source selection, independent Country/ASN health, reader lifetime and lookup cache | `offenders_geoip.py` |
| Bounded DB-IP acquisition/validation, atomic pair activation, retention and policy state | `offenders_geoip_update.py` |
| CLI dispatch | `offenders_geoip_cli.py` |
| Diagnostics, manual update and automatic-policy UI | `offenders_geoip_ui.py` |
| Source-tree compatibility wrapper | `update_geoip_db.py` |

Managed data and `state.json` live in the user-owned XDG data root. App-managed
Country/ASN files take precedence over read-only system fallback files; the two
databases retain independent health and source selection. `maxminddb` is the reader
backend. Generation changes invalidate reader/cache state without a restart.

Imports, status queries, and ordinary report construction do not fetch data.
Updates take a nonblocking writer lock, stage and validate both databases, then
atomically activate the generation reference. Retention preserves the active and
previous generation. Download size and socket-operation bounds limit acquisition;
the socket timeout is not a total wall-clock deadline for an entire update.

Automatic checks are opt-in, evaluated at dashboard startup, and rate-limited to
at most once per 24 hours; an already-current monthly generation needs no fetch.
Manual updates remain explicit. Runtime databases and policy state are never
packaged in the wheel or sdist. See the [GeoIP guide](docs/geoip.md) for paths,
operator actions, and failure states.

## Coverage and recommendation pipeline

The manual workflow is:

```text
host -> sources -> coverage + evidence -> patterns -> findings
     -> recommendations UI -> validation/custom candidate
```

| Stage | Ownership |
| --- | --- |
| Host facts | `offenders_host.py`: bounded listeners, service and systemd facts |
| Sources | `offenders_sources.py`: supported file/journal discovery and queryability |
| Coverage | `offenders_coverage.py`: runtime/static Fail2Ban facts over supplied sources |
| Evidence | `offenders_evidence.py`: bounded retained file/journal evidence and short in-process cache |
| Patterns | `offenders_patterns.py`: fixed, source-gated semantic recognizer catalog |
| Findings | `offenders_findings.py`: pure conservative correlation and decision policy |
| Presentation | `offenders_recommendations_ui.py`: manual background orchestration |
| Validation | `offenders_validation.py`, `offenders_validation_ui.py`: explicit bounded `fail2ban-regex` runs |
| Custom candidates | `offenders_candidate.py`, `offenders_candidate_ui.py`: fixed templates and disabled copy-only candidates |

Coverage and evidence receive the same source-inventory object. Findings reject
separately acquired inventories rather than correlating mismatched host state.
Evidence retains source identity and partial/unavailable/truncated outcomes, with
a short cache keyed by inventory identity and lookback. Static configuration reads
are confined and bounded; they do not implement Fail2Ban's full configuration
interpreter. Unsupported or ambiguous evidence remains a limitation.

Pattern recognition preserves UTC, local wall-clock, and unknown timestamp
domains. File mtime is not event time. Listener facts do not prove Internet
reachability; patterns do not prove maliciousness; coverage does not prove filter
suitability; validation does not prove safety.

Validation operates on retained target/context records in private temporary files.
Custom generation uses a fixed template catalog, never regex synthesis from logs.
Only the exact validated UTF-8 bytes, identified by digest and byte count, can be
shown as a candidate after the target-match gate passes. Snippets stay disabled
and copy-only. Closing a screen suppresses result delivery while bounded backend
work and cleanup may finish.

Coverage never runs during normal dashboard refresh. No path writes Fail2Ban
configuration, reloads/enables jails, or bans/unbans addresses. See the
[Coverage guide](docs/coverage.md) for the operator review workflow.

## Command and safety boundary

`offenders_fail2ban.run_host_command` accepts an argv array, uses no shell, closes
stdin, and requires an explicit positive finite timeout. It uses `sudo -n` only
when requested. Results keep stdout, stderr, return code, and failure category
separate: missing executable, timeout, nonzero exit, and OS execution failure are
distinct. A missing target behind sudo is observed as sudo's nonzero exit.
Timeout kills and reaps the direct child.

Fail2Ban queries use the sudo boundary, as does optional listener process-owner
inspection. Basic listeners, systemd/journal queries, Registration/RDNS, static config/log
reads, and regex validation use current-user permissions. Command output is
captured before downstream parse/retention caps; those caps are not streaming
subprocess-memory limits. Permission recipes belong in
[installation](docs/installation.md).

Fail2Ban inspection and configuration analysis are read-only. Normal persistent
mutation is confined to app-owned GeoIP lifecycle state; validation may create
private temporary files and cleans them after success or failure. Production
Fail2Ban changes remain outside Offenders.

### Runtime action and namespace foundation

`offenders_fail2ban.get_jail_core_status` reads only `status <jail>` and returns
the existing `JailStatus`; report acquisition still adds its best-effort numeric
settings. Explicit callers can use `get_jail_actions`, `get_action_properties`
and `get_action_property` for read-only runtime facts. These use the existing
eight-second, non-interactive sudo runner. Action identities are validated before
reuse; discovered property names never grant query permission. The finite
`ACTION_PROPERTIES` whitelist covers stock 1.0.2/1.1.0 actionban/static identifiers,
IPv6 overrides, and UFW rule/kill scope, including iptables' `lockingopt` reference.
Action text has a 64 KiB parser/retention bound and each jail has at most 32 actions;
limits reject evidence rather than silently truncating it.

`resolve_action_property` accepts normalized property mappings and resolves only
known static `<property>` references, preferring `?family=inet6` for IPv6. Its
eight-property path and 64 KiB expansion limits reject cycles, missing references
and unsupported interpolation via `Fail2BanParseError`. Dynamic ticket tags such
as `<ip>` and `<failures>` are outside this resolver. Keep actionban and dynamic
comment text as raw facts for later consumers; never execute or shell-expand them.
Upstream's ActionReader resolves definition-only tags before sending runtime
properties, including UFW's nested kill selector. Runtime reads remain the authority,
with unfamiliar/unresolved facts unavailable for a supported claim.

`action_fingerprint(jail, actions)` hashes action identities and the selected
allowlisted, normalized property values in canonical sorted order. Callers must
supply the same relevant property selection in both observations, including
IPv6 overrides; diagnostic or transient fields are rejected. It detects changes,
without classifying actions or acquiring firewall state.

`offenders_host.get_fail2ban_namespace` reads MainPID through non-sudo
`systemctl show --property=MainPID --value fail2ban.service`, then reads the
`/proc/self/ns/net` and `/proc/<pid>/ns/net` symlink identities. Its frozen result
retains PID and available identities with `same`, `different` or `unavailable`.
Command/PID/proc failures produce `unavailable`; no namespace is entered or changed.
These seams have no dashboard/report caller and perform no verification bracket
or UI orchestration. Fixture provenance and upstream limits are recorded in
[tests/fixtures/README.md](tests/fixtures/README.md).

### Native nftables direct evidence

`offenders_nftables.classify_nft_action` consumes normalized runtime properties
from the foundation. It requires the bounded stock effective `actionban` shape,
including upstream's escaped braces, and resolves static properties with the
foundation's IPv6 precedence. Only known nft executable spellings, `inet`/`ip`/`ip6`
tables, filter chains, ordinary filter hooks, and terminal drop/reject syntax
qualify. Unresolved/unsafe properties raise `Fail2BanParseError`; custom or compound
action shapes return unsupported (`None`). No action program is executed.

`read_nft_tables` takes the supported descriptors and reads each unique validated
table once using only `sudo -n nft --json --numeric list table FAMILY TABLE`
through the eight-second host-command seam. The entire batch is rejected above
32 tables; each stdout has a 4 MiB parser/retention ceiling after command capture.
There are no whole-ruleset reads or fallback commands. Failed reads, including
an absent table's nonzero command exit, are unverifiable; localized stderr never
proves absence. JSON snapshots retain only normalized facts, without raw dumps.

`verify_nft_ban` checks table presence/dormancy, simple exact IP set membership,
address type, active base/filter hook attachment, and a positive source-set match
with the configured drop/reject verdict in the same rule. The supported JSON
subset covers stock multiport/allports matches and optional counters. Prefix,
interval, timed-element and unfamiliar rule forms remain unverifiable. Reasons
are bounded identities rather than command output. These are direct backend
facts: later integration must establish namespace identity and opening/closing
ban/action stability before publishing confirmed/missing outcomes. There is no
dashboard, ordinary Report, export, or full race-bracket caller in this child.

## Packaging and distribution

`pyproject.toml` uses PEP 621 metadata and the setuptools backend. Static
`[project].version` is the sole distribution version source. The
distribution name and console command are both `offenders`, with the command
calling `offenders:main`. Python must be at least 3.12; runtime bounds are
`textual>=8.2.8,<9`, `maxminddb>=3.1,<4`, `dnspython>=2.8,<3`, and
`ipwhois>=1.3,<2`.

The explicit setuptools `py-modules` list packages the concrete runtime modules
together. Source execution also requires those modules, not a standalone script.
`scripts/check_distribution.py` checks the wheel and sdist against that contract.
Pipx provides operator isolation and is not a runtime dependency.

Build and check distributions from a clean checkout with an empty `dist/`:

```bash
python -m pip install build twine
python -m build
python -m twine check --strict dist/*
python scripts/check_distribution.py
```

The checker requires exactly one wheel and sdist, validates metadata and the
README long description, and rejects files outside the artifact allowlist.
Run it without Python's `-O` flag. The changelog is repository documentation;
it is not part of the runtime wheel.

### Release maintenance

Accumulate meaningful changes under `Unreleased` in [CHANGELOG.md](CHANGELOG.md).
Before a release, update the version in `pyproject.toml`, move those entries to
`X.Y.Z - YYYY-MM-DD`, and leave a fresh `Unreleased` section. Run the ordinary
suite and the build/distribution checks above, then tag `v<version>` and publish
a GitHub Release using that changelog section as the basis for its notes.
Approve the protected `pypi` deployment if required and verify the release on PyPI.

[The release workflow](.github/workflows/release.yml) owns publication and the
installed-wheel smoke check. It uses PyPI Trusted Publishing with the `pypi`
environment; no long-lived upload token is needed. There is no ordinary PR CI
workflow.

## Tests and evidence

Run the ordinary suite from the activated development environment:

```bash
python -m unittest discover -s tests -v
```

Use standard-library `unittest`, temporary files, and offline fixtures by default.
Prioritize behavior, safety, and regression contracts over counts or raw coverage.
Use narrow fakes/injection at external boundaries and table/subtests when they
reduce repetition. Test private helpers only for a concrete contract risk; avoid
duplicating parser/backend proof in UI tests. Textual tests should prove interaction,
report commitment, cancellation, and lifecycle behavior. Add the smallest practical
regression test for a real defect rather than a new general harness.

The ordinary suite needs no root, network, or live daemon. Optional tests using a
locally installed `fail2ban-regex` skip when the executable is absent; they exercise
synthetic samples without a daemon or host configuration mutation.
See [fixture provenance](tests/fixtures/README.md) for captured status output,
synthetic examples, upstream sources, and the limits of those fixtures.

## Source configuration

For deliberately maintained source builds, advanced constants are:

- `TOP_COUNT` and `IGNORE_PRIVATE` in [offenders_report.py](https://github.com/stef-k/Offenders/blob/master/offenders_report.py):
  Top IP ranking size and exclusion of private/loopback/link-local addresses.
- `LOG_CURRENT`, `LOG_ROTATED`, and `LOG_GZ_GLOB` in that file: report log paths.
- `CHECK_INTERVAL_SECONDS` in [offenders.py](https://github.com/stef-k/Offenders/blob/master/offenders.py): report refresh interval.

These are source edits, not settings exposed to normal pipx users. Editable
installation keeps source changes effective; package upgrades replace installed
code. Do not confuse ranking exclusions with full-period aggregate/history counts.

## Code Guard policy

The project policy is a 600 counted-LOC hard gate and a cohesion-review signal
above roughly 400 counted LOC. There is no standing `offenders.py` exemption.
REVIEW requires judgment about responsibilities and reachable risks, not mechanical
splitting. Changed-scope findings are part of implementation review.

Code Guard is external review tooling, not a checked-in project executable or
runtime dependency. In the current review environment, the installed command is:

```bash
code-guard . --changed-only --json --json-mode compact
```

Cover the complete change against its base before completion (for example, use
the tool's `--base-ref` selector for committed work). Inspect findings and required
policies; do not add exemptions or alter thresholds merely to pass.

## CSV report export (schema 1)

`offenders_export.py` owns report projection, spreadsheet-safe encoding, schemas,
private staging, and collision-safe atomic publication. It accepts a `Report`
and performs no acquisition. `offenders_export_ui.py` captures `_last_report` on
opening from the dashboard; its Textual thread worker uses the shared activity
footer and retains a literal absolute result path with clipboard/stdout fallback.
`offenders_export_cli.py` calls `build_report(period=...)` once and then the same
exporter. CLI dispatch does not construct or run a Textual application.

The compatibility surface is exactly four UTF-8 header-bearing CSVs, in this
column order (future incompatible changes require a schema-version decision):

```text
report.csv:
  schema_version,period,generated_at,window_start,total_bans,top_offender_count,jail_count,csv_text_policy
top-offenders.csv:
  rank,bans,ip,country_state,country,asn_state,asn,organization
jail-status.csv:
  jail,currently_failed,total_failed,currently_banned,total_banned,bantime_seconds,findtime_seconds,maxretry,backend,filter,current_banned_ips
ban-events.csv:
  timestamp,jail,ip
```

Metadata has one row, schema version `1`, and text policy
`apostrophe-prefix-formula-text-v1`. The centralized encoder prefixes a single
apostrophe when the first character after Unicode whitespace/C0 controls is
`=`, `+`, `-`, or `@`; normal strings stay unchanged. Numeric values and `None`
pass directly to `csv`. Every data string uses the encoder. CSV quoting preserves
commas, quotes, embedded newlines, and UTF-8 independently of formula protection.

Dates use `datetime.isoformat()` and retain local wall-clock semantics. The
`all` window start is empty. Top Offenders retain rank order and structured
Country/ASN state/value distinctions; absent legacy enrichment is unavailable,
not inferred from display placeholders. Jail rows retain daemon order, optional
absence versus zero, and stored banned-IP order in one space-separated cell.
Events retain chronological report order, equal-time order, and duplicates.
Filters, summary modes, last-ten truncation, and raw log lines do not participate.

The root defaults to `~/offenders-exports/`. Names derive from committed generation
time: `offenders-<period>-YYYY_MM_DD_THHMMSS`, followed by `-2`, `-3`, etc. on
collision. Only catalog periods are allowed. Staging is a private temporary sibling;
files are created with mode 0600, bundle directories with 0700. Linux libc
`renameat2(RENAME_NOREPLACE)` publishes without replacing even an empty directory
or a concurrent export. Unsupported platforms/filesystems fail closed; there is
no unsafe rename fallback. Atomic visibility is guaranteed, not power-loss
persistence. Handled failures clean staging; abrupt termination may leave hidden
staging. Existing destination permissions are not modified.


## Contextual Help

`offenders_help.py` owns a single opaque full-screen `HelpScreen` modal. The
app-level `action_help` admits only the explicit product-screen contexts; Help
and framework screens such as Command Palette are excluded. It pushes over the
existing screen rather than rebuilding it, preserving focus, selection, filter
and scroll while normal background updates retain their existing ownership.
Help has no workers or product actions and uses `OffendersFooter`.

The small context catalogue curates action identities/order and short prose.
`context_text` derives keys and descriptions from each source's runtime `BINDINGS`
using Textual's binding normalization, grouping aliases and qualifying conditional
copy actions. Four explicit Enter supplements cover table-selection events on the
dashboard, jail detail, IP inspector and validation; real keyboard navigation tests
prove their correspondence to runtime handlers. This is not a second key map.

Textual 8 checks priority bindings before key dispatch but filters printable keys
through the focused input's `check_consume_key`. `DashboardFilter` therefore
reserves `?`, allowing the shared priority `HELP_BINDING` to reach the app action.
GeoIP and command-output modals share that same binding because modal footer
binding chains exclude the app. Help's modal boundary blocks ordinary inherited
product actions; the app refuses recursive Help. Keep these precedence tests green
on Textual upgrades rather than adding framework-wide event interception.

`offenders_help_content.py` holds the single mini-manual and metadata helper.
Periods/default come from the report module. At app construction, installed
`importlib.metadata` Version and Project-URL fields are read once and cached;
opening Help does not read files. Missing/unreadable metadata uses a bounded
source-development version label and durable local URL fallbacks. Metadata and
all guide content render as literal `Static(markup=False)` text, without Markdown,
URL handlers or network requests. README and Usage document the global entrypoint;
external documentation remains authoritative for operational detail.
