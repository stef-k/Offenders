---
title: Offenders documentation
permalink: /
---

# Offenders documentation

Offenders investigates Fail2Ban history and live jail status from a Linux terminal.
Reports are read-only with respect to Fail2Ban configuration and bans; Coverage
results are manual and copy-only. GeoIP enrichment is optional.

## Get started

1. Read [installation and permissions](installation.md) for prerequisites,
   publication status, source installation, and rollback-safe migration.
2. Launch `offenders`, then use [usage and controls](usage.md) to explore periods,
   summaries, jails, and individual IPs.
3. Optionally configure [GeoIP and ASN enrichment](geoip.md) or run explicit
   [Coverage and validation](coverage.md).
4. Consult [troubleshooting](troubleshooting.md) for degraded or unavailable data.

The first PyPI publication is pending. Use the source workflow until publication;
installation does not download GeoIP databases or configure host permissions.

[View on GitHub](https://github.com/stef-k/Offenders) ·
[Developer appendix](https://github.com/stef-k/Offenders/blob/master/DEVELOPMENT.md) ·
[Release preparation](https://github.com/stef-k/Offenders/blob/master/RELEASING.md)
