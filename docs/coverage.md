---
title: Coverage and validation
---

# Coverage and validation

## Coverage, recommendations, and validation

Opening Coverage starts one explicit background analysis snapshot. Reopening
starts a new analysis; recently collected evidence may be reused. Normal dashboard
refresh never runs it. Analysis is independent of report health and may be partial
or unavailable because listeners, owners, journals, configuration, or logs cannot
be read. Read the source limitations alongside every result.

Host bindings do **not** establish Internet reachability. Source coverage does
not establish maliciousness, filter suitability, or that a ban should already
exist. Pattern recognition uses a fixed supported catalog of authentication
failures and specific web probes, not generic anomaly detection. Unsupported
formats remain unsupported. File evidence uses bounded current/plain-rotation
tails; Coverage does not read compressed history, unlike ordinary ban reports.
Local/unknown timestamps cannot establish an exact UTC lookback.

Recommendations ask you to review an existing disabled definition, review enabled
coverage, or investigate a supported custom gap. They are not instructions to
enable a jail. No recommendation is a normal result; suppression and evidence
summaries explain limitations. Analysis unavailable instead indicates failure.

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
