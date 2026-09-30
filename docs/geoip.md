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
checks for GeoIP updates. Use `offenders --help` for CLI discovery.

## Optional GeoIP enrichment

Offenders works without GeoIP databases. Country and ASN have independent health
snapshots. **Unmapped** means a healthy database has no mapping for
that IP; **Unavailable** means usable enrichment could not be obtained. Neither
means there were no ban events.

App-managed storage is `$XDG_DATA_HOME/offenders/geoip`, or
`~/.local/share/offenders/geoip` when unset. Use the same user and XDG environment
for the CLI and dashboard. The only supported database read paths are
`current/dbip-country-lite.mmdb` and `current/dbip-asn-lite.mmdb` under that root:

```text
geoip/
  current -> generations/<generation>/
  generations/
    <generation>/
      dbip-country-lite.mmdb
      dbip-asn-lite.mmdb
```

If `current` is missing/broken or a database is unusable, that kind remains
unavailable until a normal update activates valid data. Offenders does not
import or read databases outside this current-generation layout.

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

Diagnostics show each database's health, stable current path, resolved target,
active generation, reader availability, local age, policy, and latest
outcome. Files older than **62 local days** produce a stale warning, not invalidity;
readable data remains usable. Healthy-but-unmapped addresses
do not cause the global unavailable/stale warning.

`offenders geoip status` reports the active generation, independent Country/ASN
health, automatic policy, last check, and update outcome as JSON. Status is
read-only and performs no network access or filesystem writes. Updates use the
invoking user's data directory; use `offenders geoip update` as that user.

DB-IP Lite is licensed under **Creative Commons Attribution 4.0**. Retain
[IP Geolocation by DB-IP](https://db-ip.com) attribution when using or redistributing
it; see the [DB-IP Lite license requirements](https://db-ip.com/db/lite.php).
