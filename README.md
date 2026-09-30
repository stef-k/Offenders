# Offenders — Fail2Ban investigation and diagnostics TUI

[![PyPI](https://img.shields.io/pypi/v/offenders?label=PyPI)](https://pypi.org/project/offenders/) [![Python](https://img.shields.io/pypi/pyversions/offenders)](https://stef-k.github.io/Offenders/installation.html) [![Release checks](https://img.shields.io/github/actions/workflow/status/stef-k/Offenders/release.yml?event=release&label=release%20checks)](https://github.com/stef-k/Offenders/actions/workflows/release.yml) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/stef-k/Offenders/blob/master/LICENSE)

Offenders is a terminal-first investigation and diagnostics tool for Fail2Ban.
Combine historical ban activity with current jail state, investigate IPs and jails,
and explore IP/ASN/Country summaries over SSH or in a local Linux terminal.
Use explicit Registration/RDNS lookups, optional GeoIP, manual Coverage and
validation, CSV Export, and global contextual `? Help`.

![Offenders TUI screenshot](https://raw.githubusercontent.com/stef-k/Offenders/master/offenders-screenshot.jpg)

Current Offenders dashboard using synthetic documentation data.

- Export a committed report with `e`, or acquire one fresh CSV bundle with
  `offenders export --period 30d` (see [Usage](https://stef-k.github.io/Offenders/usage.html#csv-export)).
- Press `? Help` from any product screen for contextual controls and a concise
  in-app guide; `Esc/q` returns to your place.
- Explore rolling history periods, live jail status, and IP/ASN/Country summaries.
- Filter loaded results and investigate individual jails and IPs.
- Review Coverage evidence and explicitly validate copy-only filter candidates.
- Open manual `n Enforcement` to compare fresh current bans with supported
  nftables, iptables or UFW rule evidence; direct observation is not packet or
  reachability proof (see [Usage](https://stef-k.github.io/Offenders/usage.html#manual-enforcement-verification)).

Reports and investigation are read-only with respect to Fail2Ban configuration
and bans. There is no ban/unban action or automatic Fail2Ban mutation. Coverage
never installs filters/jails or enables/reloads Fail2Ban. Persistent application
changes are limited to explicit or opt-in GeoIP data/policy under your XDG data
root; validation also uses temporary local sample files.

## Quick start

Supported baseline: **Ubuntu 24.04 / Python >=3.12 / Fail2Ban 1.0.2**.
Qualified stock Enforcement action versions: **1.0.2, 1.1.0 and 1.1.1**;
support remains limited to recognized runtime shapes and fails closed.
Fail2Ban, readable logs, and narrowly scoped noninteractive sudo permissions must
be supplied separately; see [installation and permissions](https://stef-k.github.io/Offenders/installation.html).

Install from [PyPI](https://pypi.org/project/offenders/) and run:

```bash
pipx install offenders
offenders
```

Run `offenders --help` (or `-h`) to discover commands and their option help;
`offenders --version` (or `-V`) reports the installed version. These standalone
forms exit without launching the TUI or acquiring data.

GeoIP enrichment is optional. Installation downloads no databases; an explicit
update fetches DB-IP Lite, and automatic updates require opt-in. See the
[GeoIP guide](https://stef-k.github.io/Offenders/geoip.html) for lifecycle and attribution.
Coverage analysis and validation are explicit, manual, and copy-only; a sample
match never establishes filter safety. See [Coverage](https://stef-k.github.io/Offenders/coverage.html).

## Documentation

[Operator documentation](https://stef-k.github.io/Offenders/) ·
[PyPI](https://pypi.org/project/offenders/) ·
[Releases](https://github.com/stef-k/Offenders/releases) ·
[Changelog](https://github.com/stef-k/Offenders/blob/master/CHANGELOG.md) ·
[Development](https://github.com/stef-k/Offenders/blob/master/DEVELOPMENT.md) ·
[MIT license](https://github.com/stef-k/Offenders/blob/master/LICENSE)
