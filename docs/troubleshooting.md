---
title: Troubleshooting
---

# Troubleshooting

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| Fail2Ban command denied/unavailable, timeout, or parse failure | Read the degraded detail; verify Fail2Ban availability, actual client path, and narrowly scoped noninteractive sudo permission. Last-good data is retained; it is not current success. |
| Missing or unreadable report history | Verify configured file paths and current-user read access, including rotations. At least the current log or its plain `.1` rotation must exist; gzip history alone is insufficient. Disappearing rotations are skipped; unreadable files can fail collection. Empty history does not prove there were no bans. |
| GeoIP unavailable or reader failure | Inspect diagnostics/status for independent Country/ASN sources and reader errors; check the same user/XDG environment and file readability. Unmapped is a different state. |
| GeoIP stale | Local age exceeds 62 days; readable data remains usable. Choose an explicit update if desired. |
| GeoIP update failure | Read the latest outcome; usable active data is preserved. Check the reported network/storage/validation error before choosing another explicit attempt. |
| WHOIS/RDNS unavailable | Check the named optional tool and command failure; RDNS falls back to getent only when dig is missing. |
| Coverage partial/unavailable | Read source limitations for owner/journal/config/log access. Optional evidence failure is not proof of no exposure or complete protection. |
| Unexpected old dashboard or unrecognized GeoIP command | Use `command -v offenders` and Bash `type -a offenders` to check whether the retained standalone executable shadows pipx. |

## Configuration

There is no generic user configuration file. Periods are fixed runtime choices;
GeoIP data and automatic policy are user-owned XDG state.

For deliberately maintained **source builds**, advanced constants are:

- `TOP_COUNT` and `IGNORE_PRIVATE` in [offenders_report.py](https://github.com/stef-k/Offenders/blob/master/offenders_report.py):
  Top IP ranking size and exclusion of private/loopback/link-local addresses.
- `LOG_CURRENT`, `LOG_ROTATED`, and `LOG_GZ_GLOB` in that file: report log paths.
- `CHECK_INTERVAL_SECONDS` in [offenders.py](https://github.com/stef-k/Offenders/blob/master/offenders.py): report refresh interval.

These are source edits, not settings exposed to normal pipx users. Editable
installation keeps source changes effective; package upgrades replace installed
code. Do not confuse ranking exclusions with full-period aggregate/history counts.
