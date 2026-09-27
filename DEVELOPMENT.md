# Development and architecture

This is the maintainer reference for the current codebase. User workflows belong
in the [operator documentation](docs/README.md); artifact qualification and
publication belong in [RELEASING.md](RELEASING.md).

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
| Report-derived IP projection, inspector, WHOIS/RDNS UI | `offenders_ip.py`, `offenders_ip_ui.py` |

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
those projections, and explicit WHOIS/RDNS subprocess work run off the Textual
event loop. Screens reject stale deliveries after replacement or closure.
Navigation callbacks keep jail and IP screens independent of app imports.
See [usage](docs/usage.md) for operator controls.

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
inspection. Basic listeners, systemd/journal queries, WHOIS/RDNS, static config/log
reads, and regex validation use current-user permissions. Command output is
captured before downstream parse/retention caps; those caps are not streaming
subprocess-memory limits. Permission recipes belong in
[installation](docs/installation.md).

Fail2Ban inspection and configuration analysis are read-only. Normal persistent
mutation is confined to app-owned GeoIP lifecycle state; validation may create
private temporary files and cleans them after success or failure. Production
Fail2Ban changes remain outside Offenders.

## Packaging and distribution

`pyproject.toml` uses PEP 621 metadata and the setuptools backend. Static
`[project].version` is the sole distribution version source. The intended
distribution name and console command are both `offenders`, with the command
calling `offenders:main`. Python must be at least 3.12; runtime bounds are
`textual>=8.2.8,<9` and `maxminddb>=3.1,<4`.

The explicit setuptools `py-modules` list packages the concrete runtime modules
together. Source execution also requires those modules, not a standalone script.
`scripts/check_distribution.py` checks the wheel and sdist against that contract.
Pipx provides operator isolation and is not a runtime dependency.

Publication is isolated to `.github/workflows/release.yml`; there is no ordinary
PR CI workflow. Exact build, version/tag, installed-artifact, identity and Trusted
Publishing gates live in [RELEASING.md](RELEASING.md). Local checks do not establish
PyPI registration, an OIDC exchange, or successful publication.

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
[Fixture provenance](tests/fixtures/README.md) separates captured M6 Fail2Ban 1.0.2
status, synthetic compatible status examples, and upstream-adapted log records.
Neither synthetic 1.1.x-compatible output nor local runtime smoke proves a live
1.1.x daemon or a production deployment.

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

## Live-host qualification boundary

Keep three evidence classes separate: ordinary offline development/tests, clean
install/release-artifact qualification, and live production-host qualification.
A fixture captured on production proves only the captured command/format, not
execution of the current application revision there.

The recorded read-only M6 inspection on 2026-09-27 established Fail2Ban 1.0.2
status compatibility. The migrated M6 still runs the December 2025 standalone
application; the reviewed packaged application has not been production-deployed.
This is the current recorded deployment boundary, not a fresh host inspection.

Production inspection is read-only by default. No development/test command should
modify Fail2Ban. An explicit reviewed app-owned GeoIP update may be exercised only
when intentionally qualifying that operator action. Production deployment and
legacy-command cutover remain a separate final gate; offline tests and successful
artifact builds cannot substitute for it.
