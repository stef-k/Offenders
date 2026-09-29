"""Read iptables compatibility facts; callers own namespace and ban-race gates."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import ipaddress
import re
import shlex

from offenders_fail2ban import Fail2BanParseError, resolve_action_property, run_host_command

# Bounds apply after the existing timeout runner captures each save stdout.
IPTABLES_TEXT_LIMIT = 4 * 1024 * 1024
CHAIN_ID = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.:+-]{0,127}')
SAVE_BINARIES = {
    prefix + suffix: (prefix + suffix + '-save', version)
    for prefix, version in (('iptables', 4), ('ip6tables', 6))
    for suffix in ('', '-nft', '-legacy')
}
SAVE_VERSIONS = {binary: version for binary, version in SAVE_BINARIES.values()}
# Finite REJECT replies from the iptables/ip6tables extensions interface.
REJECT_REPLIES = {
    4: frozenset({'icmp-net-unreachable', 'icmp-host-unreachable', 'icmp-port-unreachable',
                  'icmp-proto-unreachable', 'icmp-net-prohibited', 'icmp-host-prohibited',
                  'icmp-admin-prohibited', 'tcp-reset'}),
    6: frozenset({'icmp6-no-route', 'icmp6-adm-prohibited', 'icmp6-addr-unreachable',
                  'icmp6-port-unreachable', 'icmp6-policy-fail', 'icmp6-reject-route', 'tcp-reset'}),
}
# Only stock parent scope and inert comment metadata, not arbitrary extensions.
RULE_OPTIONS = frozenset({'-s', '--source', '-j', '--jump', '-g', '--goto',
                          '-p', '--protocol', '-m', '--match', '--dport', '--dports',
                          '--destination-port', '--destination-ports', '--comment', '--reject-with'})


@dataclass(frozen=True)
class IptablesAction:
    """Resolved stock objects and a finite save selector; no action program."""

    parent_chain: str
    ban_chain: str
    ip_version: int
    target: str
    save_binary: str


@dataclass(frozen=True)
class IptablesEvidence:
    """Direct backend evidence; confirmed/missing still require the full bracket."""

    outcome: str
    reason: str


@dataclass(frozen=True)
class IptablesRule:
    """Keep direct jump/source/target facts without raw rules or match arguments."""

    chain: str
    source: str | None = None
    target: str | None = None
    supported: bool = True
    host_only: bool = False


@dataclass(frozen=True)
class IptablesSnapshot:
    """One matching compatibility save view, retaining only filter-table facts."""

    save_binary: str
    filter_present: bool = False
    chains: tuple[str, ...] = ()
    rules: tuple[IptablesRule, ...] = ()
    reason: str = ''


def _blocking_tokens(tokens: list[str], version: int) -> bool:
    """Allow DROP/REJECT and finite family-specific REJECT reply options."""
    return tokens in (['DROP'], ['REJECT']) or (
        len(tokens) == 3 and tokens[:2] == ['REJECT', '--reject-with'] and
        tokens[2] in REJECT_REPLIES[version])


def classify_iptables_action(properties: Mapping[str, str], *, family: str = 'inet4') -> IptablesAction | None:
    """Require the resolved stock actionban shape without executing shell text.

    None means unsupported syntax or semantics. Missing/unsafe/unresolved static
    properties raise the foundation parse error to retain unverifiability.
    The stock locking flag is recognized solely for selecting the save interface.
    """
    raw = properties.get('actionban', '')
    if raw.count('<ip>') != 1:
        return None
    # Other action families need not expose iptables-specific properties.
    try:
        template = shlex.split(raw)
    except ValueError:
        return None
    if '-I' not in template:
        return None
    insertion = template.index('-I')
    if template[insertion + 2:insertion + 6] != ['1', '-s', '<ip>', '-j']:
        return None
    facts = {**properties, 'actionban': raw.replace('<ip>', 'OFFENDERS_IP')}
    command = resolve_action_property(facts, 'actionban', family=family)
    values = {key: resolve_action_property(properties, key, family=family)
              for key in ('iptables', 'name', 'chain', 'blocktype')}
    ban_chain = 'f2b-' + values['name']
    if not CHAIN_ID.fullmatch(ban_chain) or not CHAIN_ID.fullmatch(values['name']) or not CHAIN_ID.fullmatch(values['chain']):
        raise Fail2BanParseError('Unsafe iptables chain identity')
    if any('\n' in value or '\r' in value for value in (command, *values.values())):
        return None
    try:
        executable = shlex.split(values['iptables'])
        blocking = shlex.split(values['blocktype'])
        tokens = shlex.split(command)
    except ValueError:
        return None
    if not executable or executable[0] not in SAVE_BINARIES or executable[1:] not in ([], ['-w']):
        return None
    save_binary, version = SAVE_BINARIES[executable[0]]
    if version != (6 if family == 'inet6' else 4) or not _blocking_tokens(blocking, version):
        return None
    expected = [*executable, '-I', ban_chain, '1', '-s', 'OFFENDERS_IP', '-j', *blocking]
    if tokens != expected:
        return None
    return IptablesAction(values['chain'], ban_chain, version, blocking[0], save_binary)


def _parse_rule(line: str, version: int) -> IptablesRule:
    """Read the finite stock option subset; unknown or negated forms stay opaque."""
    tokens = shlex.split(line)
    if len(tokens) < 4 or tokens[0] != '-A' or not CHAIN_ID.fullmatch(tokens[1]):
        raise ValueError('Invalid save rule')
    chain = tokens[1]
    fields = {}
    aliases = {'--source': '-s', '--jump': '-j', '--goto': '-g', '--protocol': '-p', '--match': '-m',
               '--destination-port': '--dport', '--destination-ports': '--dports'}
    for index in range(2, len(tokens), 2):
        option = tokens[index]
        if option not in RULE_OPTIONS:
            return IptablesRule(chain, supported=False)
        if index + 1 >= len(tokens) or tokens[index + 1].startswith('-') and option != '--comment':
            raise ValueError('Missing save option value')
        key = aliases.get(option, option)
        if key in fields:
            return IptablesRule(chain, supported=False)
        fields[key] = tokens[index + 1]
    if '-j' in fields and '-g' in fields:
        return IptablesRule(chain, supported=False)
    target = fields.get('-j')
    if target is None and '-g' not in fields:
        return IptablesRule(chain, supported=False)
    source = None
    if '-s' in fields:
        if '%' in fields['-s']:
            raise ValueError('Scoped source address')
        address = ipaddress.ip_interface(fields['-s'])
        if address.network.prefixlen == address.max_prefixlen:
            source = address.ip.compressed
    if '-m' in fields and fields['-m'] not in ('tcp', 'udp', 'multiport', 'comment'):
        return IptablesRule(chain, supported=False)
    if '--reject-with' in fields and not _blocking_tokens([target, '--reject-with', fields['--reject-with']], version):
        return IptablesRule(chain, supported=False)
    # A scoped rule does not prove the stock source-only host ban.
    host_only = fields.keys() <= {'-s', '-j', '--reject-with', '-m', '--comment'} and (
        '-m' not in fields or fields['-m'] == 'comment')
    return IptablesRule(chain, source, target, True, host_only)


def parse_iptables_save(output: str, save_binary: str) -> IptablesSnapshot:
    """Parse complete bounded save framing and only filter declarations/rules.

    Empty successful output can mean no loaded filter table. Truncated or
    ambiguous framing never proves absence. Other table rule bodies are ignored.
    """
    if save_binary not in SAVE_VERSIONS:
        return IptablesSnapshot(save_binary, reason='unsupported-save-binary')
    if len(output) > IPTABLES_TEXT_LIMIT or len(output.encode('utf-8')) > IPTABLES_TEXT_LIMIT:
        return IptablesSnapshot(save_binary, reason='evidence-limit')
    table = None
    seen = set()
    chains = set()
    rules = []
    try:
        for line in output.splitlines():
            if not line or line.startswith('#'):
                continue
            if any(ord(char) < 32 or ord(char) == 127 for char in line):
                raise ValueError('Control character in save output')
            if line.startswith('*'):
                if table is not None or line[1:] in seen or not CHAIN_ID.fullmatch(line[1:]):
                    raise ValueError('Invalid or duplicate table framing')
                table = line[1:]
                seen.add(table)
            elif line == 'COMMIT':
                if table is None:
                    raise ValueError('Unexpected COMMIT')
                table = None
            elif table is None:
                raise ValueError('Missing table header')
            elif table == 'filter':
                if line.startswith(':'):
                    match = re.fullmatch(r':([A-Za-z0-9_][A-Za-z0-9_.:+-]{0,127}) (?:-|ACCEPT|DROP) \[\d+:\d+\]', line)
                    if not match or match[1] in chains:
                        raise ValueError('Invalid or duplicate chain declaration')
                    chains.add(match[1])
                else:
                    rules.append(_parse_rule(line, SAVE_VERSIONS[save_binary]))
        if table is not None or any(rule.chain not in chains for rule in rules):
            raise ValueError('Incomplete filter evidence')
        return IptablesSnapshot(save_binary, 'filter' in seen, tuple(sorted(chains)), tuple(rules))
    except ValueError:
        return IptablesSnapshot(save_binary, reason='unrecognized-output')


def read_iptables_saves(actions: Sequence[IptablesAction]) -> dict[str, IptablesSnapshot]:
    """Read each finite matching save view once; no arguments or fallback commands."""
    snapshots = {}
    for binary in dict.fromkeys(action.save_binary for action in actions):
        if binary not in SAVE_VERSIONS:
            snapshots[binary] = IptablesSnapshot(binary, reason='unsupported-save-binary')
            continue
        result = run_host_command([binary], timeout=8, sudo=True)
        if result.failure is not None or result.returncode != 0:
            reason = result.failure.value if result.failure else 'command-failure'
            snapshots[binary] = IptablesSnapshot(binary, reason=reason)
        else:
            snapshots[binary] = parse_iptables_save(result.stdout, binary)
    return snapshots


def verify_iptables_ban(action: IptablesAction, ip: str, snapshot: IptablesSnapshot) -> IptablesEvidence:
    """Prove chain, direct parent jump, exact source host and matching block target."""
    if snapshot.reason:
        return IptablesEvidence('unverifiable', snapshot.reason)
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return IptablesEvidence('unverifiable', 'invalid-ip')
    if address.version != action.ip_version or '%' in ip:
        return IptablesEvidence('unverifiable', 'ip-family-mismatch')
    if snapshot.save_binary != action.save_binary or SAVE_VERSIONS.get(action.save_binary) != action.ip_version:
        return IptablesEvidence('unverifiable', 'snapshot-mismatch')
    if not snapshot.filter_present:
        return IptablesEvidence('missing', 'filter-table-absent')
    if action.ban_chain not in snapshot.chains:
        return IptablesEvidence('missing', 'ban-chain-absent')
    if action.parent_chain not in snapshot.chains:
        return IptablesEvidence('missing', 'parent-chain-absent')
    parents = [rule for rule in snapshot.rules if rule.chain == action.parent_chain]
    if not any(rule.supported and rule.target == action.ban_chain for rule in parents):
        if any(not rule.supported for rule in parents):
            return IptablesEvidence('unverifiable', 'unsupported-rule-expression')
        return IptablesEvidence('missing', 'parent-jump-absent')
    bans = [rule for rule in snapshot.rules if rule.chain == action.ban_chain]
    hosts = [rule for rule in bans if rule.supported and rule.host_only and rule.source == address.compressed]
    if any(rule.target == action.target for rule in hosts):
        return IptablesEvidence('confirmed', 'entry-observed')
    if any(not rule.supported or rule.source == address.compressed and not rule.host_only for rule in bans):
        return IptablesEvidence('unverifiable', 'unsupported-rule-expression')
    return IptablesEvidence('missing', 'blocking-target-absent' if hosts else 'ban-entry-absent')
