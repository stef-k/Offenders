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

Reports refresh at startup, every 30 seconds, and on request. Only one refresh
runs at a time; a manual refresh or period request while busy reports that refresh
is in progress and must be retried afterward.
The shared footer shows `⏳ Refreshing…` or a pending target such as `⏳ Loading 30d…`
while the last successful tables remain visible. A period change commits only on success. Failure retains last-known-good tables,
period, and timestamp with a degraded message; before the first success, data is
explicitly unavailable. A successful recovery replaces the data and clears the
warning. Valid zero counts are successful data.

Filtering is display-only, in memory, and never reruns collection. A trimmed,
case-insensitive literal query matches loaded IP/jail/Country/ASN/organization
fields in the summary and Last bans. Last bans enrichment is limited to IPs
already in Top IPs. Aggregate matching shows a whole bucket with its full counts,
not just matching events. The query survives refresh/period changes but not a
restart. Live jail status and investigation retain their unfiltered context.

## In-app Help

Press `? Help` from any Offenders product screen, including the focused dashboard
filter. The key is reserved for Help rather than inserted into the filter.
The first section, **Current screen**, lists that screen's controls and explains
what its data means. Below it, one concise mini-manual covers the dashboard,
investigation, Export, GeoIP, Registration/RDNS, Coverage, validation and Enforcement,
a CLI help pointer, safety distinctions, installed version and project links.

Use arrow keys, PageUp/PageDown or Home/End to scroll; `Esc/q` returns to the exact
underlying screen with its filter, selection and scroll intact. Pressing `?`
inside Help does not stack another guide. Help starts no acquisition, export or
network work and executes no product actions. Existing background work can
continue and remains visible in the normal one-row footer. URLs are literal text;
Help neither fetches remote documentation nor opens a browser. The command palette
retains its native interface.

This is a compact reference; the external documentation remains authoritative for
installation, permissions, CSV schemas and deeper operational semantics.

For command-line invocation, run `offenders --help` (or `-h`). Export and GeoIP
own their option help at `offenders export --help` and `offenders geoip --help`.
`offenders --version` (or `-V`) prints the installed distribution version, or
`offenders (source development)` when distribution metadata is unavailable.
Top-level help/version switches must be used alone; they perform no acquisition,
network requests or persistent-state work.

## Background activity

The one-row footer on every Offenders product screen, including detail and command-output modals,
combines contextual key bindings with a right-aligned `⏳ Refreshing…` activity
indicator. It appears immediately and remains visible for at least about 500 ms,
even if work has already finished. Only the visual clear is deferred: results,
navigation, cancellation, and accepting another operation remain immediate.
Overlapping work shows a primary label and `(+N)` additional workers without
flickering. Long-running work stays visible until it finishes. On narrow terminals
the label is ellipsized to at most 45% of the row; native footer bindings retain
their scrolling and click behavior. Activity never adds a row or moves content.
Framework screens such as the command palette retain their native layout.

Coverage, validation, generation, and projections retain their detailed local
loading states. Automatic refresh uses this quiet indicator without repeated
popups. Filtering, copying, and other immediate local actions do not show it.
Closing a lookup or analysis view cancels its activity and ignores late results;
the brief visual hold may remain. Closing GeoIP diagnostics leaves its
app-lifetime update running visibly.

## Key and action map

Keys are contextual: focused text input handles typing, and screen-local actions
take precedence over dashboard bindings. The map below describes supported
contexts rather than promising every app binding on every modal.

| Context | Key/action | Result |
| --- | --- | --- |
| All product screens | `?` | Open contextual Help and the complete mini-manual |
| Help | Esc / `q` | Return to the underlying screen |
| Dashboard | `q` | Quit |
| Dashboard; jail/IP detail | `r` / `p` | Refresh / request next period (when no refresh is running) |
| Dashboard | `f` | Focus filter; Enter keeps query and returns to table; Esc clears and returns |
| Dashboard | `v` | Cycle IP / ASN / Country summary |
| Dashboard | `a` | Open one Coverage analysis snapshot |
| Coverage | `p` | Switch the independent Coverage window 7d / 24h when idle (default 7d) |
| Dashboard | `n` | Open one manual Enforcement check |
| Enforcement | `r` | Recheck when idle; clear previous evidence before acquisition |
| Enforcement | Esc / `q` | Close and reject late results |
| Dashboard | `g` | Open GeoIP diagnostics |
| Dashboard tables; jail/IP detail tables; Coverage table | `c` / `x` | Copy focused row (tab-separated) or cell, according to cursor mode |
| Dashboard tables; jail/IP detail tables; Coverage table | `t` | Toggle focused table row/cell cursor mode |
| Dashboard real Top IP or Last bans row | Enter | Open IP inspector |
| Dashboard Active bans per jail row | Enter | Open jail detail |
| Dashboard real Top IP or Last bans row; IP inspector | `w` / `d` | Explicit Registration / RDNS for the selected/fixed IP |
| GeoIP diagnostics | `u` / `a` | Update now / persist automatic-policy toggle |
| GeoIP diagnostics | Esc / `q` | Close |
| Jail detail | `e` | Expand history 10 → 50 → 100 → all in period; stays at all |
| Jail history real-IP row | Enter | Open IP inspector |
| IP inspector jail row | Enter | Open jail detail |
| Jail detail; IP inspector | Esc / `q` | Back one screen |
| Command output | `c` | Copy rendered output |
| Command output | Esc / `q` | Close |
| Coverage candidate decision | `v` | Open existing-filter validation or custom-candidate screen; unavailable for suppressed rows |
| Existing-filter validation | `v` / Enter on target | Explicitly validate selected target |
| Custom candidate | `v` | Explicitly generate and validate a fixed template |
| Custom candidate | `c` | Copy only an exposed reviewable result |
| Coverage; validation; custom candidate | Esc / `q` | Close |

Aggregate rows support row/cell copying but do not represent one IP: no IP
inspector or Registration/RDNS is available from them. Last bans remains IP-navigable.
Copy actions use terminal clipboard support, with stdout fallback on a reported
clipboard exception. Command-output `c` copies output, not a table selection.

## Jail and IP investigation

Open a jail from Active bans per jail. Counters and available bantime/findtime/
maxretry settings are live values, independent of period history. Unavailable
numeric settings are not zero. Backend/filter identities appear only when
present in the report. Current banned IPs are separate from historical bans:
`(none)` means a valid empty current list, while an inactive jail has unavailable
current membership.

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
successful snapshot. Registration/RDNS are explicit on-demand network lookups,
never background enrichment. Press `w` for Registration (RDAP) or `d` for RDNS
(PTR) on the dashboard's selected IP or the inspector's fixed IP.

The output view immediately shows `Querying RDAP…` or `Resolving PTR…`, also shown
in shared activity feedback. `Esc`/`q` closes it and rejects late output. `c` copies
exactly the displayed result, including any truncation marker. Results include the
normalized IP, backend, and outcome; untrusted fields display literally with
controls flattened. Output is capped at 8,192 characters.

RDNS uses the host-configured DNS resolver with an eight-second total lifetime.
It lists sorted, deduplicated PTR names without forward confirmation or a fallback
provider. Outcomes are `success`, `no-result` (NXDOMAIN/no PTR answer), `timeout`,
`resolver-unavailable`, or `dns-failure`.

Registration uses classic `ipwhois` for shallow RDAP with an eight-second transport
timeout, zero retries, and no ASN discovery, NIR requests, or entity follow-ups.
The transport timeout is not a total wall-clock deadline across HTTP redirects.
Only available network fields such as CIDR, name, handle, country, type, status,
and address range appear; contacts and raw responses are omitted. Non-global IPs
return `not-global` without network traffic. Other outcomes are `success`,
`rate-limited`, `invalid-response`, `rdap-unavailable`, or `unexpected-failure`.
The library reports transport timeouts and other network failures together as
`rdap-unavailable`. Neither registration nor PTR data is a reputation assessment.

## Manual Enforcement verification

Press `n Enforcement` on the dashboard. Opening runs one fresh read-only check,
independently of the report's period, filter and historical logs. The summary
counts outcomes; the table retains each supported **jail / IP / runtime action /
backend** fact, and selection shows bounded reasons and sibling action names.
Two supported actions can disagree; both rows remain visible.

Offenders reads current banned IPs and allowlisted runtime action properties.
For supported actions, it proves that Fail2Ban and Offenders share a network
namespace, acquires scoped firewall views once per backend/object, then rereads
relevant bans, actions and daemon/namespace identity. Confirmation requires a
stable readable bracket and directly observed backend evidence. Unsupported
actions also receive a closing ban/action comparison, with no firewall read or
namespace requirement. Unrelated jail-list changes do not invalidate a stable
jail. Empty jails have one opening-only factual row and require no action or
firewall inspection.

| Outcome | Meaning |
| --- | --- |
| `confirmed` | The stable current ban's expected supported enforcement entry was directly observed |
| `missing` | A stable, readable comparison directly established a required fact was absent |
| `unverifiable` | Permissions, missing tools, malformed/limited output, action metadata or namespace uncertainty prevent verification |
| `unsupported-action` | Stable, fully readable opening/closing state found no supported action for this banned IP |
| `changed-during-check` | Readable relevant membership, actions, daemon PID or namespace changed during the bracket |
| `no-current-bans` | Jail-level opening snapshot has nothing to verify; no missing object is inferred |

The initial catalog covers only stock-compatible **effective runtime shapes**
for native nftables, iptables compatibility and UFW; an action name, installed
package or on-disk default does not select a backend. Unclassified or unreadable
sibling actions appear in detail without erasing an independently supported row.
Unknown/custom actions are outside the catalog, not proof of a Fail2Ban error.
UFW needs active status, exact managed-rule identity and qualified live rule
evidence. Its detail separates managed/live booleans; optional connection
termination remains `not-verified` when requested.

**Direct rule/object observation is not packet or reachability proof.** There is
no global firewall-OK verdict. Permission, parse or namespace failure never means
`missing`; a readable concurrent change outranks direct confirmed/missing
evidence. Namespace mismatch/unavailability executes no firewall command.

Press `r Recheck` when idle. Requests while running are ignored. Old rows and
detail are cleared before new acquisition; a failed recheck displays unavailable
state, preserving no old evidence as current. `Esc/q` closes and cancels screen
workers, rejecting late delivery; an already-running bounded read may finish.
The shared footer shows `Checking enforcement…`; global `? Help` remains available.
There is no timer, enforcement CLI command, persistence or firewall/Fail2Ban
mutation. Ordinary dashboard refresh and CSV Export never acquire or contain
Enforcement results. See [permissions](installation.md#optional-enforcement-read-permissions)
and [troubleshooting](troubleshooting.md#enforcement-outcomes).

## CSV export

Press `e Export` from the dashboard to open the last successfully committed
report. The screen shows its period, generation time, event count, export root,
and filenames. Press `e` again to write it. Opening and exporting acquire no new
data; a degraded dashboard exports its last-known-good snapshot with its original
period and time. Before the first success, export is unavailable. The screen
captures the report when opened; ordinary dashboard refreshes may continue behind it.

The dashboard filter is **not applied**, including when a query is active.
IP/ASN/Country mode and focused table do not affect the bundle. Export writes:

- `report.csv`: one metadata row (schema, period, timestamps, counts, text policy).
- `top-offenders.csv`: ranked Top Offenders, currently limited to 20 IPs, with
  separate mapped/unmapped/unavailable Country and ASN states.
- `jail-status.csv`: current jail counters, settings, and space-separated banned
  IPs; this state is independent of the historical period.
- `ban-events.csv`: all selected-period events, including duplicates, in report
  order; no raw log lines.

Files use UTF-8 CSV, headers, and stable columns. Missing optional fields are
empty, while zero remains zero. Timestamps retain local wall-clock semantics
without an invented timezone. Formula-like text, including after leading
whitespace/control characters, gets an apostrophe prefix; numeric fields remain
numeric. This is a spreadsheet-safe representation, not a byte-for-byte log dump.

Writing runs in the background with `⏳ Exporting…`. After success, the screen
retains **Export complete** and the exact absolute bundle path on its own line.
Use `c Copy path` (terminal clipboard, stdout fallback), or `Esc`/`q Close`.
The path remains until another export or close. Closing during writing stops UI
delivery; the already running write may still finish under the export root.

The default root is `~/offenders-exports/`. Bundle names use the report generation
time, for example `offenders-7d-2026_09_28_T192147`. Repeated exports use `-2`,
`-3`, and so on without overwriting. New bundles and files are owner-only on
Linux. All four files are staged before atomic publication; handled failures
clean up staging without presenting a partial completed bundle.

For a fresh report without launching the TUI:

```bash
offenders export
offenders export --period 30d
offenders export --period all
offenders export --period 7d --output-dir /srv/reports/offenders
```

The default period is `7d`; choices are `1h`, `24h`, `7d`, `30d`, `all`.
The CLI acquires exactly one ordinary report, using configured logs, read-only
Fail2Ban status/settings, and installed local GeoIP data. It does not start
Registration/RDNS, Coverage, or GeoIP downloads/updates. It prints the absolute
bundle path on success and exits nonzero with a bounded stderr error on failure.
`--output-dir` expands `~` and overrides the root; no scheduling is performed.
