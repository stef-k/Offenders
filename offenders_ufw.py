"""Read stock UFW rule evidence; integration owns namespace and ban-race gates."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import ipaddress
import re
import shlex

from offenders_fail2ban import ACTION_ID, Fail2BanParseError, resolve_action_property, run_host_command
from offenders_iptables import CHAIN_ID, IPTABLES_TEXT_LIMIT, REJECT_REPLIES

# Bounds apply after the existing finite-deadline runner captures stdout.
UFW_TEXT_LIMIT = IPTABLES_TEXT_LIMIT
PROFILE = re.compile(r'[A-Za-z][A-Za-z0-9_.+-]*(?: [A-Za-z0-9_.+-]+)*')
SAVE_BINARIES = {4: 'iptables-save', 6: 'ip6tables-save'}
USER_CHAINS = {4: 'ufw-user-input', 6: 'ufw6-user-input'}
IP_TAG = 'OFFENDERS_IP'
COUNT_TAG = 'OFFENDERS_FAILURES'
STOCK_COMMENT = 'by Fail2Ban after ' + COUNT_TAG + ' attempts against '


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
    """Only normalized exact source, destination, application and block facts."""

    source: str | None = None
    destination: str = ''
    application: str = ''
    target: str = ''
    comment: str = ''
    supported: bool = True


@dataclass(frozen=True)
class UfwStatus:
    """Active state and managed rows; None means state was not established."""

    active: bool | None = None
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
    masked = {key: value.replace('<ip>', IP_TAG).replace('<failures>', COUNT_TAG)
              for key, value in properties.items()}
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
    if not ACTION_ID.fullmatch(name) or not _literal(app, 128) or app and not PROFILE.fullmatch(app):
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
    kill_facts = {**masked, 'kill': masked.get('kill', ''), 'kill-mode': masked.get('kill-mode', '')}
    kill = resolve_action_property(kill_facts, 'kill', family=family)
    mode = resolve_action_property(kill_facts, 'kill-mode', family=family)
    if tail == '<kill>':
        tail = kill
    else:
        tail = tail.replace('<ip>', IP_TAG)
    try:
        if _tokens(command.splitlines()) != _tokens(expected):
            return None
        if tail and _tokens(tail.splitlines()) not in (
            _tokens(kill.splitlines()), [["ss", "-K", "dst", f'[{IP_TAG}]']],
            [["conntrack", "-D", "-s", IP_TAG]],
        ):
            return None
    except ValueError:
        return None
    return UfwAction(version, values['blocktype'], destination, app, comment, dynamic, bool(tail or kill or mode))


def _status_rule(destination: str, source: str, target: str, direction: str, comment: str) -> UfwRule:
    """Project the qualified incoming host scope; unrelated forms remain opaque."""
    try:
        address = ipaddress.ip_network(source, strict=False)
        if '%' in source or address.prefixlen != address.max_prefixlen or direction != 'IN':
            return UfwRule(supported=False)
        version = address.version
        scope = destination.removesuffix(' (v6)')
        if destination.endswith(' (v6)') and version != 6:
            raise ValueError('Mixed-family status')
        application = ''
        if scope == 'Anywhere':
            scope = 'any'
        elif scope.split(' ', 1)[0][0].isdigit() or ':' in scope.split(' ', 1)[0]:
            parts = scope.split(' ', 1)
            scope, application = parts[0], parts[1] if len(parts) == 2 else ''
        else:
            application, scope = scope, 'any'
        if application and (not PROFILE.fullmatch(application) or len(application) > 128):
            return UfwRule(supported=False)
        return UfwRule(address.network_address.compressed, _network(scope, version), application, target, comment)
    except ValueError:
        return UfwRule(supported=False)


def _bounded_output(output: str) -> bool:
    """Reject excess bytes and control text without salvaging partial evidence."""
    return len(output) <= UFW_TEXT_LIMIT and len(output.encode('utf-8')) <= UFW_TEXT_LIMIT and not any(
        ord(char) < 32 and char not in '\n\t' or ord(char) == 127 for char in output)


def parse_ufw_status(output: str) -> UfwStatus:
    """Parse only the qualified C/English UFW 0.36.2 numbered status framing."""
    if not _bounded_output(output):
        return UfwStatus(reason='evidence-limit-or-control-text')
    lines = [line.rstrip() for line in output.splitlines() if line.strip()]
    if lines == ['Status: inactive']:
        return UfwStatus(False)
    if lines == ['Status: active']:
        return UfwStatus(True)
    if len(lines) < 4 or lines[0] != 'Status: active' or lines[1].split() != ['To', 'Action', 'From'] or lines[2].split() != ['--', '------', '----']:
        return UfwStatus(reason='unrecognized-status-output')
    rules = []
    for number, line in enumerate(lines[3:], 1):
        match = re.fullmatch(r'\[\s*(\d+)\] (.+?)\s+(ALLOW|DENY|REJECT|LIMIT) (IN|OUT|FWD)\s+(.+?)(?:\s+# (.*))?', line)
        if not match or int(match[1]) != number:
            return UfwStatus(reason='unrecognized-status-output')
        rules.append(_status_rule(match[2].strip(), match[5].strip(), match[3], match[4], match[6] or ''))
    return UfwStatus(True, tuple(rules))


def _live_rule(tokens: list[str], version: int) -> UfwRule:
    """Read only stock host/destination/application blocking rules in the user chain."""
    fields = {}
    modules = []
    for index in range(2, len(tokens), 2):
        option = tokens[index]
        if option not in ('-s', '-d', '-p', '-m', '--dport', '--dports', '--comment', '-j', '--reject-with'):
            return UfwRule(supported=False)
        if index + 1 >= len(tokens):
            raise ValueError('Missing live option value')
        value = tokens[index + 1]
        if option == '-m':
            modules.append(value)
        elif option in fields:
            return UfwRule(supported=False)
        else:
            fields[option] = value
    if not fields.get('-s'):
        return UfwRule(supported=False)
    source = ipaddress.ip_network(fields['-s'], strict=False)
    if '%' in fields['-s'] or source.version != version:
        raise ValueError('Invalid source family')
    destination = _network(fields.get('-d', 'any'), version)
    target = fields.get('-j', '')
    if '--reject-with' in fields and (target != 'REJECT' or fields['--reject-with'] not in REJECT_REPLIES[version]):
        return UfwRule(supported=False)
    if any(module not in ('tcp', 'udp', 'multiport', 'comment') for module in modules):
        return UfwRule(supported=False)
    application = ''
    if '--comment' in fields:
        marker = re.fullmatch(r"\\'dapp_([A-Za-z0-9_.+%\-]+)\\'", fields['--comment'])
        if not marker:
            return UfwRule(supported=False)
        application = marker[1].replace('%20', ' ')
        if not PROFILE.fullmatch(application) or len(application) > 128 or 'comment' not in modules:
            return UfwRule(supported=False)
    ports = fields.get('--dport', fields.get('--dports', ''))
    if application:
        if fields.get('-p') not in ('tcp', 'udp') or not re.fullmatch(r'\d+(?::\d+)?(?:,\d+(?::\d+)?)*', ports):
            return UfwRule(supported=False)
    elif '-p' in fields or ports or modules:
        return UfwRule(supported=False)
    host = source.network_address.compressed if source.prefixlen == source.max_prefixlen else None
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
    """Read one fixed numbered status command; never force locale or try fallbacks."""
    result = run_host_command(['ufw', 'status', 'numbered'], timeout=8, sudo=True)
    if result.failure is not None or result.returncode != 0:
        return UfwStatus(reason=result.failure.value if result.failure else 'command-failure')
    return parse_ufw_status(result.stdout)


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
    """Require scope/block equality and, in the status layer only, the comment."""
    target = action.blocktype.upper() if frontend else {'deny': 'DROP', 'reject': 'REJECT'}[action.blocktype]
    pattern = re.escape(action.comment).replace(COUNT_TAG, r'[0-9]{1,10}') if action.dynamic_count else re.escape(action.comment)
    return any(rule.supported and rule.source == host and rule.destination == action.destination and
               rule.application == action.application and rule.target == target and
               (not frontend or re.fullmatch(pattern, rule.comment) is not None) for rule in rules)


def verify_ufw_ban(action: UfwAction, ip: str, status: UfwStatus, live: UfwLiveSnapshot) -> UfwEvidence:
    """Require active UFW and exact evidence in both independently retained layers."""
    termination = 'not-verified' if action.termination_requested else 'not-requested'
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return UfwEvidence('unverifiable', 'invalid-ip', connection_termination=termination)
    if '%' in ip or address.version != action.ip_version or live.ip_version != action.ip_version:
        return UfwEvidence('unverifiable', 'ip-family-mismatch', connection_termination=termination)
    managed = None if status.reason or status.active is None else _matching_rules(action, address.compressed, status.rules, frontend=True)
    underlying = None if live.reason else live.chain_present and _matching_rules(action, address.compressed, live.rules, frontend=False)
    outcome, reason = 'confirmed', 'entry-observed'
    if status.reason or status.active is None:
        outcome, reason = 'unverifiable', status.reason or 'status-unavailable'
    elif not status.active:
        outcome, reason = 'missing', 'ufw-inactive'
    elif live.reason:
        outcome, reason = 'unverifiable', live.reason
    elif not managed:
        opaque = any(not rule.supported for rule in status.rules)
        outcome, reason = ('unverifiable', 'unsupported-status-rule') if opaque else ('missing', 'ufw-rule-absent')
    elif not underlying:
        opaque = any(not rule.supported for rule in live.rules)
        outcome, reason = ('unverifiable', 'unsupported-live-rule') if opaque else ('missing', 'ufw-live-rule-absent')
    return UfwEvidence(outcome, reason, managed, underlying, termination)
