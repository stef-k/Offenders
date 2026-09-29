"""Read stock UFW rule evidence; integration owns namespace and ban-race gates."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
import ipaddress
import re
import shlex

from offenders_fail2ban import ACTION_ID, Fail2BanParseError, resolve_action_property, run_host_command
from offenders_iptables import CHAIN_ID, IPTABLES_TEXT_LIMIT, REJECT_REPLIES

# Bounds apply after the existing finite-deadline runner captures stdout.
UFW_TEXT_LIMIT = IPTABLES_TEXT_LIMIT
PROFILE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.+-]*(?: [A-Za-z0-9_.+-]+)*')
SAVE_BINARIES = {4: 'iptables-save', 6: 'ip6tables-save'}
USER_CHAINS = {4: 'ufw-user-input', 6: 'ufw6-user-input'}
IP_TAG = 'OFFENDERS_IP'
COUNT_TAG = 'OFFENDERS_FAILURES'
STOCK_COMMENT = 'by Fail2Ban after ' + COUNT_TAG + ' attempts against '
ADDED_HEADER = "Added user rules (see 'ufw status' for running firewall):"


@dataclass(frozen=True)
class UfwAction:
    """Resolved stock incoming scope and the optional unverified side effect."""

    ip_version: int
    blocktype: str
    destination: str
    application: str
    comment: str
    dynamic_count: bool = False
    termination_requested: bool = False


@dataclass(frozen=True)
class UfwRule:
    """Exact rule facts, or partial source/target identity for an opaque candidate."""

    source: str | None = None
    destination: str = ''
    application: str = ''
    target: str = ''
    comment: str = ''
    supported: bool = True


@dataclass(frozen=True)
class UfwStatus:
    """Runtime active state only; None means state was not established."""

    active: bool | None = None
    reason: str = ''


@dataclass(frozen=True)
class UfwManagedSnapshot:
    """Normalized added-rule identity, independent of active and live state."""

    rules: tuple[UfwRule, ...] = ()
    reason: str = ''


@dataclass(frozen=True)
class UfwLiveSnapshot:
    """Matching-family user-chain facts without retaining the raw save dump."""

    ip_version: int
    chain_present: bool = False
    rules: tuple[UfwRule, ...] = ()
    reason: str = ''


@dataclass(frozen=True)
class UfwEvidence:
    """Separate observed layers; final confirmed/missing needs the full bracket."""

    outcome: str
    reason: str
    managed_rule: bool | None = None
    live_rule: bool | None = None
    connection_termination: str = 'not-requested'


def _network(value: str, version: int) -> str:
    """Normalize explicit numeric scope; DNS, zones and mixed families fail closed."""
    if value == 'any':
        value = '::/0' if version == 6 else '0.0.0.0/0'
    network = ipaddress.ip_network(value, strict=False)
    if '%' in value or network.version != version:
        raise ValueError('Invalid UFW address family')
    return network.with_prefixlen


def _literal(value: str, limit: int) -> bool:
    """Bound static quoted fields and reject shell-active or unresolved syntax."""
    return len(value.encode('utf-8')) <= limit and all(
        char.isprintable() and char not in '"\\$`<>' for char in value)


def _profile(value: str) -> bool:
    """Use bounded non-port UFW identities; the explicit app token owns scope."""
    return len(value) <= 64 and PROFILE.fullmatch(value) is not None and value != 'all' and not value.isdecimal()


def _tokens(lines: Sequence[str]) -> list[list[str]]:
    """Tokenize each stock shell line for comparison only, never evaluation."""
    return [shlex.split(line.strip()) for line in lines if line.strip()]


def classify_ufw_action(properties: Mapping[str, str], *, family: str = 'inet4') -> UfwAction | None:
    """Require the complete stock conditional rule path and its exact static facts.

    Dynamic IP/count placeholders are masked only in the classifier; the shared
    resolver still owns bounded static substitution. Unsupported syntax returns
    None; missing/unresolved static facts raise the foundation parse error.
    """
    raw = properties.get('actionban', '')
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if len(lines) < 6 or not lines[0].startswith('if [ -n ') or lines[5] != 'fi':
        return None
    if any(IP_TAG in value or COUNT_TAG in value for value in properties.values()):
        return None
    masked = dict(properties)
    if 'comment' in masked:
        masked['comment'] = masked['comment'].replace('<failures>', COUNT_TAG)
    values = {key: resolve_action_property(masked, key, family=family)
              for key in ('add', 'blocktype', 'destination', 'application', 'comment', 'name')}
    version = 6 if family == 'inet6' else 4
    try:
        destination = _network(values['destination'], version)
    except ValueError:
        return None
    if values['add'] != 'prepend' or values['blocktype'] not in ('deny', 'reject'):
        return None
    app, comment, name = values['application'], values['comment'], values['name']
    if not ACTION_ID.fullmatch(name) or app and not _profile(app):
        return None
    dynamic = COUNT_TAG in comment
    if not _literal(comment, 256) or dynamic and comment != STOCK_COMMENT + name:
        return None
    masked['actionban'] = '\n'.join(lines[:6]).replace('<ip>', IP_TAG).replace('<failures>', COUNT_TAG)
    command = resolve_action_property(masked, 'actionban', family=family)
    rule = f'ufw prepend {values["blocktype"]} from {IP_TAG} to {values["destination"]}'
    expected = [f'if [ -n "{app}" ] && ufw app info "{app}"', 'then',
                f'{rule} app "{app}" comment "{comment}"', 'else', f'{rule} comment "{comment}"', 'fi']
    # Runtime ActionReader may have removed definition-only kill/kill-mode keys.
    tail = '\n'.join(lines[6:])
    kill_facts = {**masked, 'kill': masked.get('kill', '').replace('<ip>', IP_TAG),
                  'kill-mode': masked.get('kill-mode', '')}
    kill = resolve_action_property(kill_facts, 'kill', family=family)
    mode = resolve_action_property(kill_facts, 'kill-mode', family=family)
    if tail == '<kill>':
        if 'kill' not in properties:
            raise Fail2BanParseError('Unresolved UFW kill reference')
        tail = kill
    else:
        tail = tail.replace('<ip>', IP_TAG)
    try:
        # Preserve stock quoting: token equality alone would turn an unquoted
        # static comment containing ';' into a supported shell separator.
        if [line.strip() for line in command.splitlines()] != expected:
            return None
        if tail and _tokens(tail.splitlines()) not in (
            _tokens(kill.splitlines()), [["ss", "-K", "dst", f'[{IP_TAG}]']],
            [["conntrack", "-D", "-s", IP_TAG]],
        ):
            return None
    except ValueError:
        return None
    return UfwAction(version, values['blocktype'], destination, app, comment, dynamic, bool(tail or kill or mode))


def _bounded_output(output: str) -> bool:
    """Reject excess bytes and control text without salvaging partial evidence."""
    return len(output) <= UFW_TEXT_LIMIT and len(output.encode('utf-8')) <= UFW_TEXT_LIMIT and not any(
        ord(char) < 32 and char not in '\n\t' or ord(char) == 127 for char in output)


def parse_ufw_status(output: str) -> UfwStatus:
    """Establish active/inactive only; rendered rows carry no rule identity."""
    if not _bounded_output(output):
        return UfwStatus(reason='evidence-limit-or-control-text')
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if lines == ['Status: inactive']:
        return UfwStatus(False)
    if lines == ['Status: active']:
        return UfwStatus(True)
    if len(lines) < 4 or lines[0] != 'Status: active' or lines[1].split() != ['To', 'Action', 'From'] or lines[2].split() != ['--', '------', '----']:
        return UfwStatus(reason='unrecognized-status-output')
    return UfwStatus(True)


def _added_rule(tokens: list[str]) -> UfwRule:
    """Project only the stock extended incoming source/destination/app/comment form."""
    opaque = UfwRule(target=tokens[1].upper(), supported=False)
    if len(tokens) < 4 or tokens[:3] not in (['ufw', 'deny', 'from'], ['ufw', 'reject', 'from']):
        return opaque
    source = ipaddress.ip_network(tokens[3], strict=False)
    if '%' in tokens[3]:
        raise ValueError('Scoped source')
    host = source.network_address.compressed if source.prefixlen == source.max_prefixlen else None
    opaque = replace(opaque, source=host or source.with_prefixlen)
    remaining = tokens[4:]
    explicit_to = remaining[:1] == ['to']
    if explicit_to:
        if len(remaining) < 2:
            return opaque
        destination = _network(remaining[1], source.version)
        remaining = remaining[2:]
    elif not remaining or remaining[:1] == ['comment']:
        # UFW 0.36.2 removes exactly 'to any' when no destination port/app exists.
        destination = _network('any', source.version)
    else:
        return opaque
    app, comment = '', ''
    if remaining[:1] == ['app']:
        if not explicit_to or len(remaining) < 2 or not _profile(remaining[1]):
            return opaque
        app, remaining = remaining[1], remaining[2:]
    if remaining[:1] == ['comment']:
        if len(remaining) != 2 or len(remaining[1].encode('utf-8')) > 256:
            return opaque
        comment, remaining = remaining[1], []
    if remaining:
        return opaque
    return UfwRule(host, destination, app, tokens[1].upper(), comment)


def parse_ufw_added(output: str) -> UfwManagedSnapshot:
    """Validate the C/English added header and non-executingly tokenize each rule."""
    if not _bounded_output(output):
        return UfwManagedSnapshot(reason='evidence-limit-or-control-text')
    lines = [line for line in output.splitlines() if line.strip()]
    if len(lines) < 2 or lines[0] != ADDED_HEADER:
        return UfwManagedSnapshot(reason='unrecognized-added-output')
    if lines[1:] == ['(None)']:
        return UfwManagedSnapshot()
    rules = []
    try:
        for line in lines[1:]:
            tokens = shlex.split(line)
            if len(tokens) < 3 or tokens[0] != 'ufw' or tokens[1] not in ('allow', 'deny', 'reject', 'limit', 'route'):
                raise ValueError('Unrecognized added rule')
            rules.append(_added_rule(tokens))
        return UfwManagedSnapshot(tuple(rules))
    except ValueError:
        return UfwManagedSnapshot(reason='unrecognized-added-output')


def _live_rule(tokens: list[str], version: int) -> UfwRule:
    """Read only stock host/destination/application blocking rules in the user chain."""
    fields = {}
    modules = []
    supported = True
    for index in range(2, len(tokens), 2):
        option = tokens[index]
        if index + 1 >= len(tokens):
            raise ValueError('Missing live option value')
        if option not in ('-s', '-d', '-p', '-m', '--dport', '--dports', '--comment', '-j', '--reject-with'):
            # Unmodeled pairs cannot match, but later source/target facts can
            # exclude this rule from the expected direct ban's candidates.
            supported = False
            continue
        value = tokens[index + 1]
        if option == '-m':
            modules.append(value)
        elif option in fields:
            return UfwRule(supported=False)
        else:
            fields[option] = value
    target = fields.get('-j', '')
    opaque = UfwRule(target=target, supported=False)
    if not fields.get('-s'):
        return opaque
    source = ipaddress.ip_network(fields['-s'], strict=False)
    if '%' in fields['-s'] or source.version != version:
        raise ValueError('Invalid source family')
    host = source.network_address.compressed if source.prefixlen == source.max_prefixlen else None
    opaque = replace(opaque, source=host or source.with_prefixlen)
    destination = _network(fields.get('-d', 'any'), version)
    if not supported:
        return opaque
    if '--reject-with' in fields and (target != 'REJECT' or fields['--reject-with'] not in REJECT_REPLIES[version]):
        return opaque
    if any(module not in ('tcp', 'udp', 'multiport', 'comment') for module in modules):
        return opaque
    application = ''
    if '--comment' in fields:
        marker = re.fullmatch(r"\\'dapp_([A-Za-z0-9_.+%\-]+)\\'", fields['--comment'])
        if not marker:
            return opaque
        application = marker[1].replace('%20', ' ')
        if not _profile(application) or 'comment' not in modules:
            return opaque
    ports = fields.get('--dport', fields.get('--dports', ''))
    if application:
        if fields.get('-p') not in ('tcp', 'udp') or not re.fullmatch(r'\d+(?::\d+)?(?:,\d+(?::\d+)?)*', ports):
            return opaque
        if '--dport' in fields and '--dports' in fields or any(
            not 1 <= int(port) <= 65535 for port in re.split('[:,]', ports)):
            return opaque
    elif '-p' in fields or ports or modules:
        return opaque
    return UfwRule(host, destination, application, target)


def parse_ufw_save(output: str, version: int) -> UfwLiveSnapshot:
    """Validate complete save framing and project only the exact UFW user chain.

    Other filter rules are structural records only; no packet path or arbitrary
    chain traversal is evaluated. The #111 projection discards required scope,
    so this small projection keeps destination and UFW application markers.
    """
    if version not in USER_CHAINS or not _bounded_output(output):
        return UfwLiveSnapshot(version, reason='invalid-family-or-evidence-limit')
    table = None
    seen = set()
    chains = set()
    rule_chains = set()
    rules = []
    try:
        for line in output.splitlines():
            if not line or line.startswith('#'):
                continue
            if line.startswith('*'):
                if table is not None or line[1:] in seen or not CHAIN_ID.fullmatch(line[1:]):
                    raise ValueError('Invalid table framing')
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
                        raise ValueError('Invalid chain declaration')
                    chains.add(match[1])
                    continue
                tokens = shlex.split(line)
                if len(tokens) < 4 or tokens[0] != '-A' or not CHAIN_ID.fullmatch(tokens[1]):
                    raise ValueError('Invalid filter rule framing')
                rule_chains.add(tokens[1])
                if tokens[1] == USER_CHAINS[version]:
                    rules.append(_live_rule(tokens, version))
        if table is not None or not rule_chains <= chains:
            raise ValueError('Incomplete filter evidence')
        return UfwLiveSnapshot(version, USER_CHAINS[version] in chains, tuple(rules))
    except ValueError:
        return UfwLiveSnapshot(version, reason='unrecognized-save-output')


def read_ufw_status() -> UfwStatus:
    """Read fixed runtime status only; never force locale or try fallbacks."""
    result = run_host_command(['ufw', 'status'], timeout=8, sudo=True)
    if result.failure is not None or result.returncode != 0:
        return UfwStatus(reason=result.failure.value if result.failure else 'command-failure')
    return parse_ufw_status(result.stdout)


def read_ufw_added() -> UfwManagedSnapshot:
    """Read normalized managed rules only; never execute or replay their syntax."""
    result = run_host_command(['ufw', 'show', 'added'], timeout=8, sudo=True)
    if result.failure is not None or result.returncode != 0:
        return UfwManagedSnapshot(reason=result.failure.value if result.failure else 'command-failure')
    return parse_ufw_added(result.stdout)


def read_ufw_saves(actions: Sequence[UfwAction]) -> dict[int, UfwLiveSnapshot]:
    """Deduplicate only relevant families and read each bare save binary once."""
    snapshots = {}
    for version in dict.fromkeys(action.ip_version for action in actions):
        if version not in SAVE_BINARIES:
            snapshots[version] = UfwLiveSnapshot(version, reason='unsupported-ip-family')
            continue
        result = run_host_command([SAVE_BINARIES[version]], timeout=8, sudo=True)
        if result.failure is not None or result.returncode != 0:
            snapshots[version] = UfwLiveSnapshot(version, reason=result.failure.value if result.failure else 'command-failure')
        else:
            snapshots[version] = parse_ufw_save(result.stdout, version)
    return snapshots


def _matching_rules(action: UfwAction, host: str, rules: Sequence[UfwRule], *, frontend: bool) -> bool:
    """Require scope/block equality and, in the managed layer only, the comment."""
    target = action.blocktype.upper() if frontend else {'deny': 'DROP', 'reject': 'REJECT'}[action.blocktype]
    pattern = re.escape(action.comment).replace(COUNT_TAG, r'[0-9]{1,10}') if action.dynamic_count else re.escape(action.comment)
    return any(rule.supported and rule.source == host and rule.destination == action.destination and
               rule.application == action.application and rule.target == target and
               (not frontend or re.fullmatch(pattern, rule.comment) is not None) for rule in rules)


def _opaque_candidate(action: UfwAction, host: str, rules: Sequence[UfwRule], *, frontend: bool) -> bool:
    """Only unknown or matching source/target identity can obscure this direct ban."""
    target = action.blocktype.upper() if frontend else {'deny': 'DROP', 'reject': 'REJECT'}[action.blocktype]
    return any(not rule.supported and rule.source in (None, host) and rule.target in ('', target)
               for rule in rules)


def verify_ufw_ban(action: UfwAction, ip: str, status: UfwStatus, added: UfwManagedSnapshot, live: UfwLiveSnapshot) -> UfwEvidence:
    """Require independent active state, exact managed identity and live scope."""
    termination = 'not-verified' if action.termination_requested else 'not-requested'
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return UfwEvidence('unverifiable', 'invalid-ip', connection_termination=termination)
    if '%' in ip or address.version != action.ip_version or live.ip_version != action.ip_version:
        return UfwEvidence('unverifiable', 'ip-family-mismatch', connection_termination=termination)
    managed = None if added.reason else _matching_rules(action, address.compressed, added.rules, frontend=True)
    underlying = None if live.reason else live.chain_present and _matching_rules(action, address.compressed, live.rules, frontend=False)
    outcome, reason = 'confirmed', 'entry-observed'
    if status.reason or status.active is None:
        outcome, reason = 'unverifiable', status.reason or 'status-unavailable'
    elif not status.active:
        outcome, reason = 'missing', 'ufw-inactive'
    elif added.reason or live.reason:
        outcome, reason = 'unverifiable', added.reason or live.reason
    elif not managed:
        opaque = _opaque_candidate(action, address.compressed, added.rules, frontend=True)
        outcome, reason = ('unverifiable', 'unsupported-added-rule') if opaque else ('missing', 'ufw-rule-absent')
    elif not underlying:
        opaque = _opaque_candidate(action, address.compressed, live.rules, frontend=False)
        outcome, reason = ('unverifiable', 'unsupported-live-rule') if opaque else ('missing', 'ufw-live-rule-absent')
    return UfwEvidence(outcome, reason, managed, underlying, termination)
