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
[nftables JSON entrypoint](https://netfilter.org/projects/nftables/manpage.html).
The action template and static properties were compared using upstream Fail2Ban
[nftables.conf 1.0.2](https://github.com/fail2ban/fail2ban/blob/1.0.2/config/action.d/nftables.conf)
and [1.1.0](https://github.com/fail2ban/fail2ban/blob/1.1.0/config/action.d/nftables.conf);
their relevant semantics are identical. Inline mutations cover absent objects,
unsafe/custom actions, malformed/oversized evidence, and unsupported forms without
adding a fixture for every failure. Ordinary tests never run nft or require root.

Disposable namespace qualification also confirmed a live IPv6 allports source-set
rule with a zero counter and terminal drop, and a missing IPv4 host member. The
installed nftables 1.0.9 tool emitted incomplete JSON for a dormant table; that
read is conservatively unverifiable, without salvaging a partial snapshot.

## Iptables compatibility save output

`tests/test_iptables.py` uses small synthetic IPv4/IPv6 save snapshots with RFC
documentation addresses, chain declarations, stock multiport parent jumps,
source-only REJECT/DROP rules and RETURN tails. An unrelated `*nat` section
proves that only `*filter` facts qualify. These are not production-host captures.

The stock action template, locking flag, chain/name properties and IPv6 overrides
were compared in upstream Fail2Ban
[iptables.conf 1.0.2](https://github.com/fail2ban/fail2ban/blob/1.0.2/config/action.d/iptables.conf)
and [1.1.0](https://github.com/fail2ban/fail2ban/blob/1.1.0/config/action.d/iptables.conf);
the relevant definitions are identical. The structural save format and terminal
REJECT replies follow the iptables 1.8.10 `iptables-save(8)` and
`iptables-extensions(8)` interfaces. Inline cases cover malformed framing,
tokenization, absent direct facts, unsupported rules and exact read argv without
a backend-executable-by-parser-case matrix. Ordinary tests run no firewall tools.

Disposable user/network namespaces with iptables 1.8.10 also qualified IPv4 and
IPv6 `iptables-nft-save`/`ip6tables-nft-save` output through the pure parser and
verifier for present and absent documentation hosts. External fixture setup
created the synthetic rules; the Offenders reader contains no mutation path.
The no-argument IPv4 legacy save read could not be qualified in this environment:
`/proc/net/ip_tables_names` was permission denied. This is local parser evidence,
not supported-host, live sudo or namespace/race-bracket qualification.

## UFW status and live save output

`ufw-status.txt`, `ufw-v4.save` and `ufw-v6.save` are captures from a
disposable Ubuntu 24.04 container using UFW `0.36.2-6` and iptables
`1.8.10-3ubuntu2` (the system nft compatibility view). Setup enabled UFW and added
only documentation-address incoming rules: IPv4 REJECT, IPv4 subnet destination,
IPv4 application DENY, IPv6 DENY, and IPv6 application DENY with an exact numeric
destination. `Evidence App` is a disposable profile with TCP 22/2222 and UDP 53.
The profile spans multiple live rules but one numbered frontend row. Capture
commands were precisely `ufw status numbered`, `iptables-save` and
`ip6tables-save`, with no save arguments. No production ruleset was accessed.
Status padding at line ends and its final blank line were removed for Git diff
checks; rule content and column spacing are otherwise unchanged.

Qualification used a non-root disposable user with narrowly enumerated sudo
grants. `sudo -n ufw status numbered` produced C/English numbered headers, rows
and comments under the container's default POSIX locale. UFW's source in the
installed package (`backend_iptables.py`, `get_status`) confirms this frontend
projection, including numeric destinations and application names. Live rules
use exact `ufw-user-input`/`ufw6-user-input` chains and escaped quoted
`dapp_Evidence%20App` markers. The user-facing comment appears in status only.
This qualifies the baseline package's output contract and ordinary sudo path;
it does not claim all user locales become English, a full live systemd host,
the integration race bracket, or end-to-end packet acceptance. Localized status
is deliberately unverifiable. The product adds no locale-forcing capability.

The stock action definition was compared through GitHub's API at upstream
[Fail2Ban 1.0.2](https://github.com/fail2ban/fail2ban/blob/1.0.2/config/action.d/ufw.conf)
and [1.1.0](https://github.com/fail2ban/fail2ban/blob/1.1.0/config/action.d/ufw.conf);
the files are identical. Fixture setup is external to the backend. Ordinary
tests use these captures and small inline mutations; they never invoke UFW,
save tools, connection termination or mutation commands. The parser does not
use human `ufw show raw` output.

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
