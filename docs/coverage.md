---
title: Coverage and validation
---

# Coverage and validation

## Coverage, recommendations, and validation

Opening `a Coverage` starts one explicit background analysis with a **7d** window.
Coverage owns its raw service-evidence window independently of the dashboard's
historical Fail2Ban ban period. Local `p Coverage Period` switches **7d / 24h** and
starts one new analysis when idle; requests during analysis do not start another
run or change the committed period. The window changes only on success. Previous
rows/details are cleared before acquisition; a failed run shows **Analysis
unavailable** for the requested window. Closing/reopening starts a fresh default
7d analysis. There is no saved period preference or analysis timer. Normal dashboard
refresh never runs Coverage. Analysis is independent of report health and may be partial
or unavailable because listeners, owners, journals, configuration, or logs cannot
be read. Read the source limitations alongside every result.

Host bindings do **not** establish Internet reachability. Source coverage does
not establish maliciousness, filter suitability, or that a ban should already
exist. Pattern recognition uses a fixed supported catalog of authentication
failures and specific web probes, not generic anomaly detection. Unsupported
formats remain unsupported. File evidence uses bounded current/plain-rotation
tails, with at most one plain rotation; Coverage does not read compressed or deeper
rotations, unlike ordinary ban reports. The displayed requested UTC window does
not guarantee a complete seven-day history.
Local/unknown timestamps cannot establish an exact UTC lookback.

Recommendations ask you to review an existing disabled definition, review enabled
coverage, or investigate a supported custom gap. They are not instructions to
enable a jail. The **Disposition** table shows every analysis decision in its
existing order, including candidates and suppressed/insufficient decisions.
Select any row to inspect its exact reason, service/source, pattern counts/times,
current coverage, retained examples and limitations without further acquisition.
**Suppressed / not a recommendation** rows explain below-threshold activity,
non-global-only IPs, inactive services, compatible enabled coverage below tuning
thresholds, or insufficient evidence. They remain explanations, not recommendations.
**No recommendation** is a normal headline when there are no candidates; suppressed
rows remain inspectable. A genuinely empty decision table retains source-analysis
context. **Analysis unavailable** instead indicates workflow failure.

`v Validate` is available only for a selected candidate: it opens existing-filter
validation for disabled/enabled review candidates, or the custom-candidate screen
for a custom gap. Suppressed rows cannot start validation or generation. `c` / `x`
copy the selected row/cell, `t` switches row/cell cursor mode, `?` opens Help, and
Esc / `q` closes Coverage. Dashboard refresh, filter, Export, GeoIP and lookup
actions are unavailable on this screen.

Existing-filter validation requires explicit target selection and execution;
opening/highlighting alone does not validate. It tests samples from the analysis
snapshot with installed `fail2ban-regex`, without sudo or DNS lookups. It does not
read fresh logs or change configuration. Counts describe tested
lines, which may differ from logical records. Success means the tested sample
matched, **never that a filter is safe**. Context is not a known-clean corpus:
context matches need review and zero matches do not prove low false-positive risk.
Missing context evidence is unavailable, not zero.

Custom generation supports only fixed Nginx/Apache sensitive-dotfile and
path-traversal gaps. It does not generate generic regexes or duplicate known stock
authentication patterns. Filter/jail snippets are exposed only when their exact
filter text validates with all tested target lines matched and none missed/ignored.
Partial results retain their limitations. Withheld results cannot be copied.

Candidates start `enabled = false`, inherit local ban policy for operator review,
and are copy-only. Offenders does not daemon-test generated candidates, write
suggested configuration files, install/enable/reload jails, or ban or unban an IP.
Review evidence and local policy independently before any manual use.
