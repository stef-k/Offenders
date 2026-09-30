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
| Manual Enforcement models and bracketed backend orchestration | `offenders_enforcement.py` |
| Enforcement screen, recheck and result presentation | `offenders_enforcement_ui.py` |
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

The current asynchronous audit covers these worker paths:

| Trigger | Worker / feedback |
| --- | --- |
| Initial report, timer, refresh, period, GeoIP activation | `_collect_report`: refreshing or pending period |
| GeoIP mount / opted-in startup update | `_startup`: checking, then updating |
| GeoIP Update now | `update_now`: updating |
| GeoIP automatic-policy toggle | `toggle_auto`: saving policy |
| Explicit Registration / RDNS | `CommandOutputModal._run`: provider-specific working text |
| IP mount / successful new report | `IPInspectorScreen._project`: loading details |
| Coverage mount | `_analyze`: analyzing coverage |
| Enforcement mount / idle recheck | `_check`: checking enforcement |
| Selected filter validation | `_validate`: validating |
| Custom template action | `_generate`: generating and validating |
| ASN/Country selection / successful new report | `DashboardSummary._project`: loading summary |

Filtering, copy, cursor movement, jail-history expansion, back navigation, and
ordinary snapshot rendering remain immediate/local. Mount/navigation that starts
one of the workers above inherits activity automatically. Duplicate report,
GeoIP, validation, and candidate actions retain their single-flight rejection
feedback. `tests/test_activity.py` audits runtime scheduling for unmanaged work
and proves generic participation; existing product tests cover detailed states.

## Manual Enforcement boundary

`check_enforcement()` acquires a fresh snapshot through the foundation's core
status and finite action-property APIs, independently of `Report`. Opening and
closing use the same observation builder; fingerprints hash discovered action
identities and exact queried allowlisted facts. Safe jail/action selectors use
the foundation's bounded identity grammar. A jail without current bans needs no
actions or firewall bracket. Namespace proof precedes every firewall reader.

Three explicit classifiers select exactly one descriptor per action/IP family;
ambiguity fails closed. A supported action can coexist with unclassified or
unreadable siblings. Backend acquisition remains scoped: nft table scopes,
iptables save binaries and UFW families are deduplicated by their reviewed
readers. UFW status and added rules are acquired once per check. Separate
iptables and UFW reads remain separate evidence contracts even when both use
the same save binary; there is no command cache or backend framework.

Closing unreadability takes precedence over readable relevant change, which
takes precedence over direct backend evidence. Relevant current-ban sets and
action identities are compared independently of unrelated jail-list changes.
Required action facts/descriptors and readable daemon/namespace identities are
bracketed. Unreadable siblings do not erase supported action rows. Final immutable
results retain stable reasons, bounded sibling identities and UFW managed/live
facts, with no raw commands, dumps or diagnostic streams.

Fully readable unsupported action rows also compare closing jail membership and
action facts. They acquire no firewall evidence and require no namespace equality.
Opening metadata-unavailable rows remain unverifiable; only `no-current-bans`
intentionally reports opening membership without a closing comparison.

The screen owns one Textual thread worker per opening/idle recheck, clears rows
before reacquiring, and rejects cancelled/replaced/closed delivery. Generation
and immutable row identity form table keys so queued events cannot select a new
check's same-looking row. It uses shared selection helpers and `OffendersFooter`;
there is no enforcement timer, CLI/export schema or persistence. Cancellation
does not terminate a bounded host read already executing.

Focused tests cover bracketing and cross-backend batching at public seams, then
real Textual lifecycle/selection/Help controls. Package qualification is separate
from representative systemd/Fail2Ban host acceptance. The latter requires
independent review of the exact draft PR head first; keep #113 draft/unmerged and
#83 open until that evidence and the parent checklist are reconciled. The
operator sudoers example must be syntax-checked and exercised as a non-root
user on supported Ubuntu 24.04. Disposable synthetic rule evidence does not
prove packet blocking or qualify a representative live host.

## GeoIP lifecycle

| Responsibility | Module |
| --- | --- |
| Current-generation reads, independent Country/ASN health, reader lifetime and lookup cache | `offenders_geoip.py` |
| Bounded DB-IP acquisition/validation, atomic pair activation, retention and policy state | `offenders_geoip_update.py` |
| CLI dispatch | `offenders_geoip_cli.py` |
| Diagnostics, manual update and automatic-policy UI | `offenders_geoip_ui.py` |
| Source-tree compatibility wrapper | `update_geoip_db.py` |

Managed data and `state.json` live in the user-owned XDG data root. The sole read
paths are `current/dbip-{country,asn}-lite.mmdb`, where `current` points to an
atomically activated directory under `generations/`. Each database has one
immutable health snapshot containing its stable path, resolved target, file
identity, reader availability and validity. Country/ASN remain independent;
there are no alternate-source reads. `maxminddb` is the reader backend.
Refresh pins the current pair once; changed file identities invalidate their
readers and lookup caches without a restart. Lookup corruption closes the
affected reader until refresh observes a valid replacement.

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

The Coverage screen explicitly passes its local 7d/24h lookback through
`run_analysis(lookback)` to the collector; the generic collector default stays
24h. Opening uses 7d and local period changes run single-flight, clearing old
evidence before acquisition and committing the period/result only on success.
The full-screen modal exposes existing ordered decisions, gates validation by
candidate class and isolates dashboard bindings. Policy and thresholds stay in
`offenders_findings.py`; no period persistence or automatic analysis is added.

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
It also permits raw `actionstart` reads/fingerprints, without adding that command
to `ACTION_BASE_PROPERTIES` or enabling static resolution of it or `known/*`.
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
`systemctl show --property=MainPID --value fail2ban.service`, then reads
`/proc/self/ns/net` directly and the validated `/proc/<pid>/ns/net` through the
bounded `sudo -n /usr/bin/readlink` seam. It immediately re-reads MainPID non-sudo;
only the same nonzero PID permits comparison of the exact `net:[N]` identities.
Its frozen result retains PID and available identities with `same`, `different`
or `unavailable`. Command/PID/proc failures and an unstable PID produce
`unavailable` without retaining the privileged identity. The opening/closing
Enforcement bracket remains the outer race check; no namespace is entered or changed.
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
facts: `offenders_enforcement` establishes namespace identity and opening/closing
ban/action stability before publishing confirmed/missing outcomes. The backend
itself has no Textual, ordinary Report or export responsibility.

### Iptables compatibility direct evidence

`offenders_iptables.classify_iptables_action` consumes the foundation's normalized
properties and requires the stock effective
`<iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>` shape. It resolves `name`,
parent `chain`, `blocktype` and the IPv4/IPv6 `iptables` property, including the
stock `lockingopt` reference. Only bare `iptables`, `iptables-nft`,
`iptables-legacy` and their `ip6tables` equivalents, optionally followed by `-w`,
qualify. Custom executable paths, wrappers, compound commands, arbitrary targets
and extra executable flags are unsupported. Missing, unsafe or unresolved
properties raise `Fail2BanParseError`; supported targets are DROP and REJECT,
including finite family-specific REJECT replies.

Concrete runtime `chain` values keep the static resolution path. Only an exact
raw `chain=<known/chain>` uses the public raw `actionstart` value instead: this
config-reader sentinel is not a readable `CommandAction` property. The shared
observation builder excludes `actionstart` from normal advertised-property reads
and acquires it only when advertised and the successfully read chain is exactly
that sentinel. Its exact value participates in both bracket fingerprints.

The bounded start matcher accepts exactly two stock forms: the 1.0.2/1.1.0 direct
parent and the 1.1.1 single-parent chain iterator. Both require the stock RETURN-tail
setup, one protocol loop, identical oneport/multiport/allports scope and the exact
already-derived `f2b-<name>` target. Direct `-C`/`-I` parents must agree on one
concrete `CHAIN_ID`. The iterator requires the exact stock
`for chain in $(echo '<PARENT>' | sed 's/,/ /g')` structure, one concrete `CHAIN_ID`
source, literal `$chain` in both rules and balanced `done; done` closure. Both
normalize to the same descriptor parent. Missing, unresolved, unsafe, multiple-parent
or custom syntax remains unverifiable. This raw text is never statically resolved,
shell-evaluated or executed. It supplies expected configuration only; the existing
save verifier independently proves the live parent jump and host rule.

`read_iptables_saves` reads each selected compatibility view once through
`sudo -n <matching-binary>-save`, with **no arguments** and an eight-second
deadline. Iptables-nft uses its matching save interface rather than native nft
object-name guesses. No action program, mutation, restore or fallback command
is run. No-argument save avoids requesting that a missing table module be loaded.
The 4 MiB parser/retention bound applies after the existing runner captures stdout;
excess evidence, failed reads and malformed framing remain unverifiable.

`parse_iptables_save` reads only `*filter` chain declarations and stock structural
rule facts with `shlex.split`; other table rule bodies cannot satisfy a check.
Snapshots retain normalized chains, direct jumps, exact host sources and targets,
without raw rules or command diagnostics. `verify_iptables_ban` requires the
expected Fail2Ban chain, configured parent chain, a direct parent jump and an
exact source-only host rule with the configured terminal DROP/REJECT target.
Bare hosts and /32 or /128 normalize identically; networks, unrelated chains and
custom jump paths cannot confirm a ban. Unfamiliar relevant rule forms stay
unverifiable, and no recursive chain traversal or packet-path evaluation occurs.
`offenders_enforcement` owns namespace and opening/closing ban/action stability
gates; this backend has no Textual, ordinary Report or export responsibility.

### UFW direct evidence

`offenders_ufw.classify_ufw_action` requires the complete stock Fail2Ban
1.0.2/1.1.0 conditional UFW rule path, with `prepend`, `deny`/`reject`, a numeric
destination (or `any`), and an empty or bounded application-profile identity
(up to 64 characters, including numeric-leading names but excluding bare ports).
IP-looking application identities remain applications through the explicit
`app` token in the managed projection; rendered status rows establish no scope.
It consumes foundation runtime properties without executing the action text.
The resolved rule lines retain stock quoting; shell token equality alone cannot
establish compatibility when a literal field becomes an unquoted operator.
Comments may be empty, bounded static literals, or the stock
`by Fail2Ban after <failures> attempts against <name>` template. Only that
template permits a dynamic field: one to ten ASCII decimal count digits, with
the resolved name exact. Other unresolved/static substitutions retain the
foundation parse error; custom action syntax is unsupported.

`read_ufw_status` runs only `sudo -n ufw status` for active/inactive state.
`read_ufw_added` separately reads `sudo -n ufw show added` for managed identity.
`read_ufw_saves` deduplicates relevant IP families and runs only bare
`sudo -n iptables-save` or `sudo -n ip6tables-save`. Each uses the existing
eight-second command deadline and a 4 MiB parser/retention bound after capture.
There is no locale wrapper, fallback, action execution or mutation command.
The status contract is qualified C/English UFW 0.36.2; localized or unfamiliar
framing stays unverifiable. Failed status reads leave active state unknown,
distinct from a successful installed/active or installed/inactive observation.

`parse_ufw_status` retains active state only and discards rendered rule rows.
`parse_ufw_added` validates the English header and uses non-executing `shlex`
tokenization for the finite incoming `ufw deny|reject from <host> to <destination>`
form, with optional `app <profile>` and comment. It also accepts UFW 0.36.2's
canonical source-only omission of `to any`, with at most a comment and no app,
port, protocol, direction/interface, route or other scope tokens. That form can
match only an expected anywhere destination and empty application. Malformed
or unfamiliar evidence cannot establish authoritative absence.
`parse_ufw_save` validates save framing and keeps only
the matching `ufw-user-input` or `ufw6-user-input` chain's live scope and target.
It reuses #111's identical bounds, chain grammar and finite REJECT replies;
the reviewed iptables projection/parser is unchanged because it intentionally
discards UFW's required destination/application scope. No generic parser or
frontend model is introduced. Snapshots retain no raw firewall dumps.

`verify_ufw_ban` requires separate active status, exact managed identity and live
rule evidence. The three snapshots remain independently available to integration.
`deny` corresponds to DROP and `reject` to REJECT. Numeric destinations normalize
as networks; sources must be exact hosts. Application rules require the exact
`dapp_<profile>` live marker, with spaces encoded as `%20`. The expected user
comment belongs only to the added-rule layer. Managed/live presence remain separate
nullable facts; unavailable evidence is not authoritative absence. Optional
`kill`/`kill-mode` behavior is retained as `connection_termination=not-verified`;
no connection tool runs. Unfamiliar relevant rule restrictions fail closed.
Opaque rules retain any established source and action/target identity: ordinary
managed `allow`, `limit` and `route` rules and live nonblocking targets cannot
hide an absent direct ban. Unsupported rules for another source or blocking
action/target also cannot hide absence. Unknown or matching candidate identity
remains unverifiable; malformed or incomplete snapshot framing still invalidates
the evidence as a whole.

The Ubuntu 24.04 disposable-container captures and sudo/locale qualification are
documented in [fixture provenance](tests/fixtures/README.md#ufw-status-and-live-save-output).
They establish the output contract, not full supported-host acceptance. Later
`offenders_enforcement` owns namespace and opening/closing action/ban stability
gates; this backend has no Textual, ordinary Report/export or timer responsibility.
Direct rule observation does not prove packet reachability or arbitrary UFW
before/after rule correctness. #113 owns the consolidated feature changelog.

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

`OffendersApp.check_action()` owns inherited app-action availability for native
Footer rendering and Textual action dispatch. Dashboard navigation, Quit and
selected-IP lookups are dashboard-only; report Refresh/Period also admit Jail
Detail and IP Inspector. Generic copy/cursor controls require product-table focus;
copy reuses the handler's selection and dashboard identity guards. Local screen
bindings retain precedence and their existing conditional checks. Native focus
changes refresh bindings. Focused table highlights and explicit empty/replaced
detail results refresh copy availability where Textual emits no focus change;
do not add periodic visibility refresh or a second binding/footer/palette
registry. Framework commands remain Textual-owned.

`offenders_help.py` owns a single opaque full-screen `HelpScreen` modal. The
app-level `action_help` admits only the explicit product-screen contexts; Help
and framework screens such as Command Palette are excluded. It pushes over the
existing screen rather than rebuilding it, preserving focus, selection, filter
and scroll while normal background updates retain their existing ownership.
Help has no workers or product actions and uses `OffendersFooter`.

The small context catalogue curates action identities/order and short prose.
`context_text` derives keys and descriptions from local and inherited runtime `BINDINGS`,
keeping local key ownership, grouping aliases and qualifying focus- or result-dependent
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

`offenders_help_content.py` holds the single mini-manual and the shared
`installed_version()` authority for CLI/TUI version reporting. Periods/default
come from the report module. At app construction, installed `importlib.metadata`
version and Project-URL fields are read and cached;
opening Help does not read files. Missing/unreadable metadata uses a bounded
source-development version label and durable local URL fallbacks. Metadata and
all guide content render as literal `Static(markup=False)` text, without Markdown,
URL handlers or network requests. README and Usage document the global entrypoint;
external documentation remains authoritative for operational detail.
