# Changelog

Notable changes to Offenders are recorded here.

## Unreleased

- Read GeoIP only from app-managed atomic `current` generations; remove flat-XDG
  and system fallback reads, and simplify database health, diagnostics and status
  JSON while preserving updater safety and publication fallback (#124).

- Omit uncollected Backend/Filter fields from Jail Detail while preserving
  numeric unavailable values and CSV export compatibility (#121).

- Default Coverage to an independent 7d window with local 7d/24h switching;
  expose suppressed decisions and their reasons, keep validation candidate-only,
  and show only working Coverage controls (#120).

- Add top-level `--help`/`-h` CLI discovery and `--version`/`-V` installed-version
  reporting without acquisition; share the TUI version authority and point TUI
  command guidance to CLI help (#108).

- Add manual `n Enforcement` verification for stock-compatible runtime nftables,
  iptables and UFW actions, with namespace-gated, batched read-only evidence and
  race-safe before/after checks. Preserve separate action/IP outcomes, idle-only
  recheck, safe empty/stale selection, shared activity and Help; document narrow
  read permissions and the limits of direct observation. Ordinary reports and
  CSV exports remain independent (#83, #113).

## 0.3.1 - 2026-09-29

- Harden empty, invalid and stale TUI selections and result-dependent actions;
  prevent the Coverage empty-highlight crash and unintended navigation, validation or copy.

## 0.3.0 - 2026-09-29

- Refresh public investigation/diagnostics positioning, discovery metadata, and
  the current dashboard screenshot using synthetic documentation data (#97).

- Validate Fail2Ban wall-clock ranges explicitly so malformed timestamps such as
  `24:00:00` remain rejected on Python 3.14; preserve fractions, calendar-date
  validation, and naive local timestamps (#101).

- Add global `? Help` with runtime-derived contextual controls, one scrollable
  mini-manual, current CLI guidance and installed version/project links. Preserve
  underlying screen state and start no acquisition or network work (#85).

- Add shared spreadsheet-safe CSV report bundles through dashboard `e Export`
  and headless `offenders export`. Retain committed TUI snapshots and copyable
  result paths; acquire exactly one fresh CLI snapshot. Publish four private
  files atomically under `~/offenders-exports/` with collision suffixes (#84).

## 0.2.1 - 2026-09-28

- Move shared background activity into a universal one-row footer with native
  key bindings, a compact hourglass and overlap count, and bounded narrow-terminal
  labels. Keep fast activity visible for about 500 ms without delaying results;
  include command-output modals and remove the separate top status row (#93).
  Product screens compose the footer explicitly; framework screens such as the
  command palette retain their native layout.

- Ship canonical PyPI and Documentation project URLs in distribution metadata for
  the first time, with refreshed README badges and documentation links.

## 0.2.0 - 2026-09-28

- Package Python-native Registration (RDAP, retaining `w`) and RDNS (PTR) lookups;
  remove separate lookup-tool prerequisites, bound and normalize literal results,
  skip registration traffic for non-global IPs, and reuse shared activity feedback.
- Shared background activity feedback across all screens, including pending report
  periods, GeoIP updates, and immediate lookup status; preserve last-good data and
  explain duplicate requests while work is active.

## 0.1.0 - 2026-09-28

- Terminal dashboard for Fail2Ban history and live jail status, with rolling
  periods, filtering, IP/ASN/Country summaries, and jail/IP investigation.
- Explicit WHOIS/RDNS lookups and optional DB-IP Country/ASN enrichment, with
  rootless updates, independent database health, and opt-in automatic updates.
- Manual Coverage analysis, existing-filter validation, and disabled, copy-only
  custom filter candidates. Offenders never changes Fail2Ban configuration or bans.
- Bounded noninteractive host commands and last-known-good reports on refresh
  failure, with unavailable data distinguished from valid empty results.
- Installable Python package with the `offenders` command and operator documentation.
