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
| Refresh/GeoIP operation already in progress | The request was not queued or started again. Retry after the operation finishes; the footer indicator may linger briefly after completion. A pending period label does not change the committed report. |
| GeoIP update failure | Read the latest outcome; usable active data is preserved. Check the reported network/storage/validation error before choosing another explicit attempt. |
| Registration/RDNS request failed | Read the outcome: check host DNS configuration for `resolver-unavailable`, DNS reachability for `timeout`/`dns-failure`, and outbound RDAP access for `rdap-unavailable`. `no-result` means no PTR answer; `not-global` skips registration traffic. A rate limit requires waiting before another explicit request. |
| Coverage partial/unavailable | Read source limitations for owner/journal/config/log access. Optional evidence failure is not proof of no exposure or complete protection. |
| Unexpected old dashboard or unrecognized GeoIP command | Use `command -v offenders` and Bash `type -a offenders` to check whether the retained standalone executable shadows pipx. |

## Configuration

There is no generic user configuration file. Periods are fixed runtime choices;
GeoIP data and automatic policy are user-owned XDG state.

Registration/RDNS dependencies are installed with Offenders. A missing Python
import indicates an incomplete installation: reinstall the package in its pipx
environment. A temporary request failure does not disable either action.

## Enforcement outcomes

Enforcement is manual (`n` on the dashboard, then idle-only `r Recheck`). It has
no effect on the ordinary dashboard's permission requirements or refresh health.
Read the selected row's stable reason and backend evidence reason:

| Evidence/reason | What to check |
| --- | --- |
| `namespace-mismatch` / `namespace-unavailable` | Non-sudo systemctl MainPID and current-user proc namespace access. No firewall command ran. Offenders does not switch namespaces or guess a fallback. |
| `closing-namespace-unavailable` / `closing-state-unavailable` / `closing-action-unavailable` | The closing bracket could not be read sufficiently. Retry explicitly after checking daemon/runtime read access; this is not a missing rule. |
| `non-zero-exit`, `command-not-found`, `timeout` | Resolve actual tool paths and narrowly scoped noninteractive read permissions. Command stderr is intentionally not published. |
| Action metadata unavailable / `ambiguous-action` | Runtime properties could not establish exactly one supported family. Do not infer a backend from the action name or loosen command permissions. |
| `unsupported-action` | Readable runtime action shapes are outside the finite catalog. A custom/notification action is not automatically harmless or broken. |
| `changed-during-check` | Current membership, action facts or daemon/namespace identity changed. Choose Recheck when idle; no old direct evidence is labeled current. |
| `missing` | The stable readable comparison found a specific required fact absent. Inspect that fact through normal administrator tools; Offenders performs no repair. |
| `no-current-bans` | Nothing was banned in that jail's opening snapshot. On-demand firewall objects were not inspected or declared missing. |

UFW's managed and live rule facts are independent; an installed or active UFW
alone cannot confirm a ban. Optional connection termination is not verified.
Parser/evidence limits remain `unverifiable`, never absence. A failed recheck
clears previous successful rows. Direct rule/object observation is not packet or
reachability proof, even when the selected row is `confirmed`.

## CSV export fails

Check that the destination root (default `~/offenders-exports/`) is writable by
the account running Offenders, parent directories are traversable, and the volume
has free space. The CLI can choose a writable root with `--output-dir`; existing
root permissions are preserved. Avoid running as root merely to export.

Exports require Linux atomic no-replace rename support in libc, the kernel, and
the destination filesystem. Unsupported filesystems fail rather than overwrite
existing exports. Try a local Linux filesystem if publication is unsupported.
A handled write/publication failure removes temporary staging; completed exports
remain untouched. An abrupt process termination may leave a hidden
`.offenders-export-*` staging directory, which is not a completed export.
The TUI retains the committed report on failure, so it can be retried. If no
report has succeeded yet, resolve the report acquisition error first.
