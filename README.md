# Offenders (Fail2Ban TUI)

[![PyPI](https://img.shields.io/pypi/v/offenders?label=PyPI)](https://pypi.org/project/offenders/) [![Python](https://img.shields.io/pypi/pyversions/offenders)](https://stef-k.github.io/Offenders/installation.html) [![Release checks](https://img.shields.io/github/actions/workflow/status/stef-k/Offenders/release.yml?event=release&label=release%20checks)](https://github.com/stef-k/Offenders/actions/workflows/release.yml) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Offenders is a Linux terminal dashboard for Fail2Ban history and live jail status.
Inspect banned IPs, ASN/Country summaries, jail settings and current membership;
run on-demand Registration/RDNS lookups or a manual Coverage analysis for review.

![Offenders TUI screenshot](https://raw.githubusercontent.com/stef-k/Offenders/master/offenders-screenshot.jpg)

Current dashboard with synthetic documentation addresses and no GeoIP databases.

- Explore rolling history periods, live jail status, and IP/ASN/Country summaries.
- Filter loaded results and investigate individual jails and IPs.
- Review Coverage evidence and explicitly validate copy-only filter candidates.

Reports and investigation are read-only with respect to Fail2Ban configuration
and bans. There is no ban/unban action or automatic Fail2Ban mutation. Coverage
never installs filters/jails or enables/reloads Fail2Ban. Persistent application
changes are limited to explicit or opt-in GeoIP data/policy under your XDG data
root; validation also uses temporary local sample files.

## Quick start

Supported baseline: **Ubuntu 24.04 / Python >=3.12 / Fail2Ban >=1.0.2**.
Fail2Ban, readable logs, and narrowly scoped noninteractive sudo permissions must
be supplied separately; see [installation and permissions](https://stef-k.github.io/Offenders/installation.html).

Install from [PyPI](https://pypi.org/project/offenders/) and run:

```bash
pipx install offenders
offenders
```

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
