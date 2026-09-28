# Changelog

Notable changes to Offenders are recorded here.

## Unreleased

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
