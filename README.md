# Offenders (Fail2Ban TUI)

Offenders is a Linux terminal dashboard for Fail2Ban history and live jail status.
Inspect banned IPs, ASN/Country summaries, jail settings and current membership;
run on-demand WHOIS/RDNS lookups or a manual Coverage analysis for review.

![Offenders TUI screenshot](https://raw.githubusercontent.com/stef-k/Offenders/master/offenders-screenshot.jpg)

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
The package supplies `textual>=8.2.8,<9` and `maxminddb>=3.1,<4`.
Fail2Ban, readable logs, and narrowly scoped noninteractive sudo permissions must
be supplied separately; see [installation and permissions](docs/installation.md).

**First PyPI publication is pending.** The intended distribution name is
`offenders`; registration and Trusted Publishing acceptance remain unproven.
After publication, the primary Linux install/run path is:

```bash
pipx install offenders
offenders
```

Until then, from a repository checkout with Python's venv support installed:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
offenders
```

GeoIP enrichment is optional. Installation downloads no databases; an explicit
update fetches DB-IP Lite, and automatic updates require opt-in. See the
[GeoIP guide](docs/geoip.md) for lifecycle and attribution.
Coverage analysis and validation are explicit, manual, and copy-only; a sample
match never establishes filter safety. See [Coverage](docs/coverage.md).

## Documentation

The repository documentation is available now. The
[Pages documentation site](https://stef-k.github.io/Offenders/) is the intended
published location; repository Pages setup and live-site qualification are pending.

- [Documentation home](docs/README.md)
- [Installation, upgrades, permissions, and migration](docs/installation.md)
- [Usage and authoritative controls](docs/usage.md)
- [GeoIP and ASN enrichment](docs/geoip.md)
- [Coverage and validation](docs/coverage.md)
- [Troubleshooting and source configuration](docs/troubleshooting.md)

[Repository](https://github.com/stef-k/Offenders) ·
[Releases](https://github.com/stef-k/Offenders/releases) ·
[Developer appendix](DEVELOPMENT.md) · [Release preparation](RELEASING.md) ·
[MIT license](LICENSE)
