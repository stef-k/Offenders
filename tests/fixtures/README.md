# Fail2Ban status fixtures

`status-1.0.2-live.txt` and `status-sshd-1.0.2-live.txt` preserve stdout from
read-only `sudo -n /usr/bin/fail2ban-client status` and `status sshd` inspection
on 2026-09-27. The inspected server reported Fail2Ban 1.0.2: eight jails and zero
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
