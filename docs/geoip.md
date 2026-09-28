---
title: GeoIP and ASN enrichment
---

# GeoIP and ASN enrichment

## Run and CLI

Run `offenders` from any directory after installation, as the user with the
[installation permissions](installation.md). The supported application forms are:

```bash
offenders                       # dashboard
offenders geoip status          # read-only local health and policy
offenders geoip update          # explicit download and activation
offenders geoip auto on         # persist opt-in for future launches
offenders geoip auto off        # persist disabled policy (the default)
```

Status, local reads, imports, and lookups never download. Manual update performs
network access and writes user-owned data. Automatic policy is off by default;
changing it persists local state. The normal 30-second report refresh never
checks for GeoIP updates. There are no top-level `--help`, `--version`, or generic
configuration commands.

## Optional GeoIP enrichment

Offenders works without GeoIP databases. Country and ASN have independent health
and source selection. **Unmapped** means a healthy database has no mapping for
that IP; **Unavailable** means usable enrichment could not be obtained. Neither
means there were no ban events.

Preferred storage is `$XDG_DATA_HOME/offenders/geoip`, or
`~/.local/share/offenders/geoip` when unset. Use the same user and XDG environment
for the CLI and dashboard. Existing flat files there remain readable. Legacy
`/usr/share/GeoIP/dbip-{country,asn}-lite.mmdb` files are read-only fallback,
selected independently when preferred Country or ASN data is missing/unhealthy.
Updates never modify those system files.

The first explicit update is consent to download DB-IP Lite Country and ASN data
into user-owned storage. Updates validate both files before activation; failed
acquisition preserves usable active data. Successful activation becomes visible
without restarting through normal report refresh. A dashboard update requests a
refresh; if collection is already running, the next normal refresh picks it up.
Diagnostics show update errors separately from report health. The shared footer activity
indicator shows startup checks, `Updating GeoIP…`, and policy persistence. An accepted
update immediately replaces the previous feedback, then shows activation, no
update needed, or an error. Repeating Update now or toggling policy while a GeoIP
operation is active reports that it is already in progress. Closing diagnostics
does not cancel the app-lifetime operation.

Automatic updates require opt-in. Enabling the policy takes effect at the next
dashboard launch: one check runs after mount, subject to a 24-hour check interval.
An already activated current UTC month is not downloaded again automatically;
a previous-month publication fallback can retry after 24 hours. Manual updates
are explicit and run regardless of that automatic schedule.

Diagnostics show each source, reader health, path, local age, policy, and latest
outcome. Files older than **62 local days** produce a stale warning, not invalidity;
readable data remains usable. Healthy fallback and healthy-but-unmapped addresses
do not cause the global unavailable/stale warning.

If migrating from a system-wide GeoIP updater, retire its root cron invocation
when switching to Offenders-managed updates. Updates use the invoking user's
data directory; use `offenders geoip update` as that user.

DB-IP Lite is licensed under **Creative Commons Attribution 4.0**. Retain
[IP Geolocation by DB-IP](https://db-ip.com) attribution when using or redistributing
it; see the [DB-IP Lite license requirements](https://db-ip.com/db/lite.php).
