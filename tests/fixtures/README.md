# Fixture provenance

`status-1.0.2-live.txt` and `status-sshd-1.0.2-live.txt` preserve stdout from
read-only `sudo -n /usr/bin/fail2ban-client status` and `status sshd` inspection
on M6 on 2026-09-27. The inspected server reported Fail2Ban 1.0.2: eight jails and zero
current/total bans in sshd. No server mutation was performed.

`status.txt` and `status-sshd.txt` are synthetic representative outputs, covering
multiple jails and a nonzero current-ban count distinct from total bans and failed
attempts. Their status tree and field format is shared by Fail2Ban 1.0.2 and 1.1.0;
these fixtures are not captures from a live 1.1.x daemon.

The upstream client formatters were compared at tags
[1.0.2](https://github.com/fail2ban/fail2ban/blob/1.0.2/fail2ban/client/beautifier.py)
and [1.1.0](https://github.com/fail2ban/fail2ban/blob/1.1.0/fail2ban/client/beautifier.py).
The latter adds `status --all` handling and statistics output; Offenders uses
neither. Plain `status` and `status <jail>` retain the relevant fields and layout.
The tests also assert those exact command forms so integration does not silently
start depending on newer options.

## Pattern recognition examples

`tests/test_patterns.py` contains adapted, synthetic representative log lines based
on the [Fail2Ban 1.0.2 log fixtures](https://github.com/fail2ban/fail2ban/tree/1.0.2/fail2ban/tests/files/logs)
for `sshd`, `dovecot`, `vsftpd`, `proftpd`, `pure-ftpd`, `nginx-http-auth`,
`apache-auth`, and `nginx-botsearch`. Addresses, dates, usernames, and hostnames are
test values. Additional path-category and timestamp-domain cases exercise the
pattern recognition contract; these are not production captures or failregex qualification.
The Apache nested-client negative example and PAM `ruser=rhost=...` case protect
source-field attribution. Localized Pure-FTPd messages deliberately remain
unrecognized. Fixtures are embedded in the compact public-projection table so
expected family, kind, and source IP stay next to the representative line.
The vsftpd PAM program-envelope regression preserves the exact upstream 1.0.2
line, including its original address, and verifies source-family gating.

## Local and production evidence

`tests/test_candidate_templates.py` optionally runs the local `fail2ban-regex`
executable against synthetic records and temporary configuration. It skips when
that executable is absent; it needs no running daemon and does not alter host
Fail2Ban configuration. Other validation tests use bounded-command fakes.

Offline parser/UI tests and installed-runtime smoke qualify local contracts only.
The captured status fixtures do not establish current-revision execution on M6.
The recorded deployment boundary remains the December 2025 standalone application
on the migrated M6; the reviewed packaged application has not been deployed there.
Production deployment qualification is a separate gate. See
[development evidence](../../DEVELOPMENT.md#tests-and-evidence) and
[release qualification](../../RELEASING.md#local-qualification).
