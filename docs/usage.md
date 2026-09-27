---
title: Usage and controls
---

# Usage and controls

## Dashboard, history, and refresh

The default period is **7d**. Choices cycle
`1h -> 24h -> 7d -> 30d -> all -> 1h`. Finite periods are rolling local-time windows
(7d is 168 hours; 30d is 720), from the lower boundary through the report time.
`all` uses every parsed event in available logs, without time boundaries.
Current and rotated logs, including gzip history, contribute events; malformed
records are skipped. Source timestamps without offsets remain local wall-clock
values: timezone/DST ambiguity cannot be recovered. Tables display seconds.

Historical counts and Last bans describe the committed period; current jail
counters and banned addresses describe the live Fail2Ban snapshot. Top IPs can
exclude private, loopback, and link-local addresses. ASN/Country summaries count
all committed-period events, including repeated bans and private/local addresses
outside the Top IP ranking. Aggregate rows show ban and distinct-IP counts with
separate mapped, Unmapped, and Unavailable buckets. Their totals can exceed the
visible Top IP total. Last bans displays the newest ten events.

Startup, the 30-second timer, manual refresh, period changes, and post-update
refresh share **one active report build**. Requests during a build do not cancel
or queue work; manual refresh/period requests report that refresh is in progress.
A period change commits only on success. Failure retains last-known-good tables,
period, and timestamp with a degraded message; before the first success, data is
explicitly unavailable. A successful recovery replaces the data and clears the
warning. Valid zero counts are successful data.

Filtering is display-only, in memory, and never reruns collection. A trimmed,
case-insensitive literal query matches loaded IP/jail/Country/ASN/organization
fields in the summary and Last bans. Last bans enrichment is limited to IPs
already in Top IPs. Aggregate matching shows a whole bucket with its full counts,
not just matching events. The query survives refresh/period changes but not a
restart. Live jail status and investigation retain their unfiltered context.

## Key and action map

Keys are contextual: focused text input handles typing, and screen-local actions
take precedence over dashboard bindings. The map below describes supported
contexts rather than promising every app binding on every modal.

| Context | Key/action | Result |
| --- | --- | --- |
| Dashboard | `q` | Quit |
| Dashboard; jail/IP detail | `r` / `p` | Refresh / request next period, sharing the single-build gate |
| Dashboard | `f` | Focus filter; Enter keeps query and returns to table; Esc clears and returns |
| Dashboard | `v` | Cycle IP / ASN / Country summary |
| Dashboard | `a` | Open one Coverage analysis snapshot |
| Dashboard | `g` | Open GeoIP diagnostics |
| Dashboard tables; jail/IP detail tables | `c` / `x` | Copy focused row (tab-separated) or cell, according to cursor mode |
| Dashboard tables; jail/IP detail tables | `t` | Toggle focused table row/cell cursor mode |
| Dashboard real Top IP or Last bans row | Enter | Open IP inspector |
| Dashboard Active bans per jail row | Enter | Open jail detail |
| Dashboard real Top IP or Last bans row; IP inspector | `w` / `d` | Explicit WHOIS / RDNS for the selected/fixed IP |
| GeoIP diagnostics | `u` / `a` | Update now / persist automatic-policy toggle |
| GeoIP diagnostics | Esc / `q` | Close |
| Jail detail | `e` | Expand history 10 → 50 → 100 → all in period; stays at all |
| Jail history real-IP row | Enter | Open IP inspector |
| IP inspector jail row | Enter | Open jail detail |
| Jail detail; IP inspector | Esc / `q` | Back one screen |
| Command output | `c` | Copy rendered output |
| Command output | Esc / `q` | Close |
| Coverage finding | `v` | Open existing-filter validation or custom-candidate screen |
| Existing-filter validation | `v` / Enter on target | Explicitly validate selected target |
| Custom candidate | `v` | Explicitly generate and validate a fixed template |
| Custom candidate | `c` | Copy only an exposed reviewable result |
| Coverage; validation; custom candidate | Esc / `q` | Close |

Aggregate rows support row/cell copying but do not represent one IP: no IP
inspector or WHOIS/RDNS is available from them. Last bans remains IP-navigable.
Copy actions use terminal clipboard support, with stdout fallback on a reported
clipboard exception. Command-output `c` copies output, not a table selection.

## Jail and IP investigation

Open a jail from Active bans per jail. Counters and available bantime/findtime/
maxretry settings are live values, independent of period history. Unavailable
settings are not zero; backend/filter identity may be unavailable. Current banned
IPs are separate from historical bans: `(none)` means a valid empty current list,
while an inactive jail has unavailable current membership.

Jail history is newest first and expands within the selected period. Opening or
expanding detail reuses the last successful report without extra collection.
Expansion survives refresh and period changes; reopening starts at ten.

Open an IP from a real Top IP, Last bans, or jail-history row. Its inspector shows
period ban count, first/last seen, distinct jails, per-jail counts, newest ten
events, report timestamp, and independent Country/ASN states. Current membership
is separate from period history. Enter on an inspector jail opens its detail;
back navigation preserves the underlying jail/IP context and history expansion.
Returning to the dashboard reselects the IP when present.

Successful refresh/period changes update open jail/IP views in place, even if the
selected IP disappears from history or current bans. Failures retain the last
successful snapshot. WHOIS/RDNS are explicit on-demand network tools, never
background enrichment. Commands run without sudo with eight-second timeouts and
no retries; output shows command, stdout/stderr, and failure category. Displayed
and copied output is capped at approximately 200 KiB.
