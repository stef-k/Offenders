# Fixture provenance

`status-1.0.2-live.txt` and `status-sshd-1.0.2-live.txt` are sanitized Fail2Ban 1.0.2
stdout captures obtained through read-only `sudo -n /usr/bin/fail2ban-client status`
and `status sshd` calls. They exercise jail-list parsing and extraction of the
currently banned count from the status tree.

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

## Runtime action output

`actions.txt` and `actionproperties.txt` are adapted representative stdout, with
synthetic jail/action identities. They cover the distinct comma-list envelopes
for action discovery and public property discovery. Empty sentinels, one action,
raw property values and malformed cases are small inline examples in
`tests/test_actions.py`. These are not captures from live daemons.

Compared upstream transmitter and beautifier code at tags
[1.0.2 transmitter](https://github.com/fail2ban/fail2ban/blob/1.0.2/fail2ban/server/transmitter.py),
[1.1.0 transmitter](https://github.com/fail2ban/fail2ban/blob/1.1.0/fail2ban/server/transmitter.py),
[1.0.2 beautifier](https://github.com/fail2ban/fail2ban/blob/1.0.2/fail2ban/client/beautifier.py),
and [1.1.0 beautifier](https://github.com/fail2ban/fail2ban/blob/1.1.0/fail2ban/client/beautifier.py).
Both versions provide jail/action identities in the list headers, use comma-space
separators and explicit empty sentinels, and return raw attribute values for
`get <jail> action <action> <property>` without an identity envelope. Public names
can include non-whitelisted properties such as `timeout`; discovery does not
authorize their acquisition.

The finite property whitelist and resolution subset derive from stock
[nftables](https://github.com/fail2ban/fail2ban/blob/1.0.2/config/action.d/nftables.conf),
[iptables](https://github.com/fail2ban/fail2ban/blob/1.0.2/config/action.d/iptables.conf),
and [ufw](https://github.com/fail2ban/fail2ban/blob/1.0.2/config/action.d/ufw.conf)
definitions and their 1.1.0 counterparts. Relevant definitions are unchanged
between these tags (only spelling corrections in nftables/iptables comments).
`addr_set`, `blocktype` and `iptables` have stock IPv6 conditional overrides;
`iptables` references `lockingopt`. Upstream
[ActionReader](https://github.com/fail2ban/fail2ban/blob/1.0.2/fail2ban/client/actionreader.py)
and [config conversion](https://github.com/fail2ban/fail2ban/blob/1.0.2/fail2ban/client/configreader.py)
resolve definition-only static tags before exporting runtime values, including
UFW's nested kill selector. Dynamic `<ip>`/`<failures>` tags are not static
properties for Offenders to resolve. These source comparisons establish the
shared read/normalization contract, not backend classification, firewall state,
live sudo permissions or expanded distro support.

## Native nftables JSON

`nft-table.json` adapts a scoped `nft --json --numeric list table inet evidence`
read from nftables 1.0.9 in a disposable user/network namespace. The IPv4 multiport
rule, embedded simple set elements, numeric reject reply and base-chain fields
were captured directly; the IPv6 set/rule is a synthetic extension of that same
schema. All addresses are RFC documentation addresses. It is not a production
ruleset or a capture from the supported Ubuntu 24.04 host baseline.

The parser subset follows the installed `libnftables-json(5)` schema and upstream
[nftables JSON documentation](https://netfilter.org/projects/nftables/manpage.html#lbBO).
The action template and static properties were compared using upstream Fail2Ban
[nftables.conf 1.0.2](https://github.com/fail2ban/fail2ban/blob/1.0.2/config/action.d/nftables.conf)
and [1.1.0](https://github.com/fail2ban/fail2ban/blob/1.1.0/config/action.d/nftables.conf);
their relevant semantics are identical. Inline mutations cover absent objects,
unsafe/custom actions, malformed/oversized evidence, and unsupported forms without
adding a fixture for every failure. Ordinary tests never run nft or require root.

## Pattern recognition examples

`tests/test_patterns.py` contains adapted, synthetic representative log lines based
on the [Fail2Ban 1.0.2 log fixtures](https://github.com/fail2ban/fail2ban/tree/1.0.2/fail2ban/tests/files/logs)
for `sshd`, `dovecot`, `vsftpd`, `proftpd`, `pure-ftpd`, `nginx-http-auth`,
`apache-auth`, and `nginx-botsearch`. Addresses, dates, usernames, and hostnames are
test values. Additional path-category and timestamp-domain cases exercise the
pattern recognition contract; they do not prove that a Fail2Ban filter matches
those records.
The Apache nested-client negative example and PAM `ruser=rhost=...` case protect
source-field attribution. Localized Pure-FTPd messages deliberately remain
unrecognized. Fixtures are embedded in the compact public-projection table so
expected family, kind, and source IP stay next to the representative line.
The vsftpd PAM program-envelope regression preserves the exact upstream 1.0.2
line, including its original address, and verifies source-family gating.

These fixtures establish parser and recognition behavior for the supplied records,
not execution against a live daemon. See [development tests](../../DEVELOPMENT.md#tests-and-evidence)
for the ordinary offline suite and optional local filter-template tests.
