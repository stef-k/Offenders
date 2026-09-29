"""Read scoped native nftables facts; callers own namespace and ban-race gates."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import ipaddress
import json
import re

from offenders_fail2ban import Fail2BanParseError, resolve_action_property, run_host_command

# Bounds apply after the existing timeout runner captures each scoped stdout.
NFT_TEXT_LIMIT = 4 * 1024 * 1024
NFT_TABLE_LIMIT = 32
NFT_ID = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.:+-]{0,127}')
NFT_FAMILIES = frozenset({'inet', 'ip', 'ip6'})
NFT_HOOKS = frozenset({'prerouting', 'input', 'forward', 'output', 'postrouting'})


@dataclass(frozen=True)
class NftAction:
    """Only normalized expected objects; no executable action program is retained."""

    table_family: str
    table: str
    chain: str
    chain_hook: str
    addr_set: str
    ip_version: int
    verdict: str


@dataclass(frozen=True)
class NftEvidence:
    """Direct backend evidence only; confirmed/missing still need the full bracket."""

    outcome: str
    reason: str


@dataclass(frozen=True)
class NftSet:
    """Keep exact simple host members or an explicit unsupported representation."""

    name: str
    address_type: str
    members: tuple[str, ...]
    supported: bool


@dataclass(frozen=True)
class NftChain:
    """Normalize only base-chain facts needed to establish hook attachment."""

    name: str
    chain_type: str | None
    hook: str | None
    priority_present: bool


@dataclass(frozen=True)
class NftRule:
    """Retain source-set wiring/verdict evidence, never raw rule expressions."""

    chain: str
    references: tuple[str, ...]
    source_set: str | None
    ip_version: int | None
    verdict: str | None
    supported: bool


@dataclass(frozen=True)
class NftSnapshot:
    """One normalized table read shared by actions, with no retained raw dump."""

    table_family: str
    table: str
    present: bool = False
    dormant: bool = False
    sets: tuple[NftSet, ...] = ()
    chains: tuple[NftChain, ...] = ()
    rules: tuple[NftRule, ...] = ()
    reason: str = ''


def _safe_table(family: str, table: str) -> bool:
    """Validate the entire privileged selector before constructing any nft argv."""
    return family in NFT_FAMILIES and bool(NFT_ID.fullmatch(table))


def classify_nft_action(properties: Mapping[str, str], *, family: str = 'inet4') -> NftAction | None:
    """Match the bounded stock effective actionban, without shell evaluation.

    None means unsupported shape/semantics. Missing, unsafe or unresolved static
    facts raise the foundation parse error so callers can retain unverifiability.
    Upstream stores shell-escaped braces; an already effective literal form also
    qualifies. The only dynamic tag accepted is exactly one whole <ip> token.
    """
    raw = properties.get('actionban', '')
    if raw.count('<ip>') != 1:
        return None
    facts = dict(properties)
    facts['actionban'] = raw.replace('<ip>', 'OFFENDERS_IP')
    command = resolve_action_property(facts, 'actionban', family=family)
    command = command.replace(r'\{', '{').replace(r'\}', '}')
    if '\n' in command or '\r' in command:
        return None
    values = {key: resolve_action_property(properties, key, family=family) for key in (
        'table_family', 'table', 'chain', 'chain_type', 'chain_hook', 'addr_set', 'blocktype')}
    if not _safe_table(values['table_family'], values['table']) or any(
        not NFT_ID.fullmatch(values[key]) for key in ('chain', 'addr_set')
    ):
        raise Fail2BanParseError('Unsafe nftables object identity')
    expected = ['add', 'element', values['table_family'], values['table'],
                values['addr_set'], '{', 'OFFENDERS_IP', '}']
    tokens = command.split()
    if not tokens or tokens[0] not in ('nft', '/usr/sbin/nft', '/sbin/nft') or tokens[1:] != expected:
        return None
    if values['chain_type'] != 'filter' or values['chain_hook'] not in NFT_HOOKS:
        return None
    # Finite blocking syntax only, including stock-compatible reject replies.
    blocktype = values['blocktype']
    if blocktype not in ('drop', 'reject') and not re.fullmatch(
        r'reject with (?:tcp reset|(?:icmp|icmpv6|icmpx) type '
        r'(?:no-route|host-unreachable|port-unreachable|admin-prohibited|addr-unreachable))', blocktype
    ):
        return None
    version = 6 if family == 'inet6' else 4
    if values['table_family'] not in ('inet', 'ip6' if version == 6 else 'ip'):
        return None
    return NftAction(values['table_family'], values['table'], values['chain'],
                     values['chain_hook'], values['addr_set'], version, blocktype.split()[0])


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    """Ambiguous JSON keys must not silently overwrite earlier evidence."""
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError('Duplicate nft JSON key')
    return result


def _parse_set(value: dict) -> NftSet:
    """Normalize only unadorned host addresses; reject ranges and stateful sets."""
    members = []
    supported = not value.get('flags') and not any(key in value for key in ('timeout', 'gc-interval'))
    elements = value.get('elem', [])
    if not isinstance(elements, list):
        supported = False
        elements = []
    for elem in elements:
        try:
            if not isinstance(elem, str) or '%' in elem:
                raise ValueError('Not a simple address')
            members.append(ipaddress.ip_address(elem).compressed)
        except ValueError:
            supported = False
    address_type = value.get('type')
    if not isinstance(address_type, str):
        supported = False
        address_type = ''
    return NftSet(value['name'], address_type, tuple(members), supported)


def _parse_rule(value: dict) -> NftRule:
    """Recognize stock positive source-set matches and terminal drop/reject.

    Protocol/port matches and counters may precede the terminal verdict. Other
    expression forms referencing a set remain explicitly unsupported rather than
    being ignored while claiming that the rule blocks the member.
    """
    expressions = value.get('expr')
    if not isinstance(expressions, list) or not expressions:
        raise ValueError('Invalid nft rule expressions')
    references = []
    source_set = version = verdict = None
    supported = True
    for index, expression in enumerate(expressions):
        if not isinstance(expression, dict) or len(expression) != 1:
            raise ValueError('Invalid nft statement')
        kind, statement = next(iter(expression.items()))
        if kind == 'match' and isinstance(statement, dict):
            right = statement.get('right')
            left = statement.get('left')
            if isinstance(right, str) and right.startswith('@'):
                references.append(right[1:])
                payload = left.get('payload') if isinstance(left, dict) else None
                if (source_set is None and set(statement) == {'left', 'right', 'op'} and statement.get('op') == '==' and
                        payload in ({'protocol': 'ip', 'field': 'saddr'}, {'protocol': 'ip6', 'field': 'saddr'})):
                    source_set = right[1:]
                    version = 4 if payload['protocol'] == 'ip' else 6
                else:
                    supported = False
            elif not _stock_scope_match(statement):
                supported = False
        elif kind == 'counter' and isinstance(statement, dict):
            continue
        elif index == len(expressions) - 1 and kind == 'drop' and statement is None:
            verdict = 'drop'
        elif index == len(expressions) - 1 and kind == 'reject' and isinstance(statement, dict):
            if set(statement) <= {'type', 'expr'} and statement.get('type') in (None, 'icmp', 'icmpv6', 'icmpx', 'tcp reset') and (
                'expr' not in statement or isinstance(statement['expr'], (str, int))
            ):
                verdict = 'reject'
            else:
                supported = False
        elif kind not in ('accept', 'jump', 'goto', 'return', 'continue') or index != len(expressions) - 1:
            supported = False
    return NftRule(value['chain'], tuple(references), source_set, version, verdict, supported)


def _stock_scope_match(match: dict) -> bool:
    """Allow the stock multiport/allports scope, without interpreting packet paths."""
    if set(match) != {'left', 'right', 'op'} or match.get('op') != '==':
        return False
    left = match.get('left')
    return left in ({'payload': {'protocol': 'tcp', 'field': 'dport'}},
                    {'payload': {'protocol': 'udp', 'field': 'dport'}},
                    {'meta': {'key': 'l4proto'}}) and isinstance(match.get('right'), (str, int, dict))


def _table_objects(data: object, family: str, table: str) -> dict[str, list[dict]]:
    """Validate the list envelope and scoped identities before proving absence."""
    if not isinstance(data, dict) or set(data) != {'nftables'} or not isinstance(data['nftables'], list):
        raise ValueError('Invalid nft list envelope')
    objects = {key: [] for key in ('table', 'set', 'chain', 'rule')}
    identities = set()
    for entry in data['nftables']:
        if not isinstance(entry, dict) or len(entry) != 1:
            raise ValueError('Invalid nft list object')
        kind, value = next(iter(entry.items()))
        if not isinstance(value, dict):
            raise ValueError('Invalid nft object value')
        if kind == 'metainfo':
            if value.get('json_schema_version') != 1:
                raise ValueError('Unknown nft JSON schema')
            continue
        if kind not in objects:
            raise ValueError('Unsupported nft object')
        name_key = 'chain' if kind == 'rule' else 'name'
        if not isinstance(value.get(name_key), str):
            raise ValueError('Missing nft object name')
        if value.get('family') != family or value.get('name' if kind == 'table' else 'table') != table:
            raise ValueError('Unexpected nft table identity')
        identity = (kind, value[name_key])
        if kind != 'rule' and identity in identities:
            raise ValueError('Duplicate nft object')
        identities.add(identity)
        objects[kind].append(value)
    return objects


def parse_nft_table(output: str, family: str, table: str) -> NftSnapshot:
    """Project bounded table JSON to direct facts; unfamiliar output fails closed."""
    if not _safe_table(family, table):
        return NftSnapshot(family, table, reason='unsafe-identifier')
    if len(output) > NFT_TEXT_LIMIT or len(output.encode('utf-8')) > NFT_TEXT_LIMIT:
        return NftSnapshot(family, table, reason='evidence-limit')
    try:
        data = json.loads(output, object_pairs_hook=_unique_object)
        objects = _table_objects(data, family, table)
        flags = objects['table'][0].get('flags', []) if objects['table'] else []
        if not isinstance(flags, list) or any(flag not in ('dormant', 'owner', 'persist') for flag in flags):
            raise ValueError('Unknown nft table flags')
        sets = tuple(_parse_set(value) for value in objects['set'])
        chains = tuple(NftChain(value['name'], value.get('type'), value.get('hook'),
                               type(value.get('prio')) is int) for value in objects['chain'])
        rules = tuple(_parse_rule(value) for value in objects['rule'])
        return NftSnapshot(family, table, bool(objects['table']), 'dormant' in flags, sets, chains, rules)
    except (ValueError, TypeError, KeyError, RecursionError):
        return NftSnapshot(family, table, reason='unrecognized-output')


def read_nft_tables(actions: Sequence[NftAction]) -> dict[tuple[str, str], NftSnapshot]:
    """Read each validated table once; the only command path is a scoped list."""
    keys = tuple(dict.fromkeys((action.table_family, action.table) for action in actions))
    snapshots = {}
    for family, table in keys:
        reason = ''
        if len(keys) > NFT_TABLE_LIMIT:
            reason = 'evidence-limit'
        elif not _safe_table(family, table):
            reason = 'unsafe-identifier'
        if reason:
            snapshots[(family, table)] = NftSnapshot(family, table, reason=reason)
            continue
        result = run_host_command(['nft', '--json', '--numeric', 'list', 'table', family, table], timeout=8, sudo=True)
        if result.failure is not None or result.returncode != 0:
            # Never interpret localized stderr as a successful absent-table fact.
            reason = result.failure.value if result.failure else 'command-failure'
            snapshots[(family, table)] = NftSnapshot(family, table, reason=reason)
        else:
            snapshots[(family, table)] = parse_nft_table(result.stdout, family, table)
    return snapshots


def verify_nft_ban(action: NftAction, ip: str, snapshot: NftSnapshot) -> NftEvidence:
    """Prove only direct table/set/member/base-chain/source-rule/verdict facts."""
    if snapshot.reason:
        return NftEvidence('unverifiable', snapshot.reason)
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return NftEvidence('unverifiable', 'invalid-ip')
    if address.version != action.ip_version or '%' in ip:
        return NftEvidence('unverifiable', 'ip-family-mismatch')
    if (snapshot.table_family, snapshot.table) != (action.table_family, action.table):
        return NftEvidence('unverifiable', 'snapshot-mismatch')
    if not snapshot.present:
        return NftEvidence('missing', 'table-absent')
    if snapshot.dormant:
        return NftEvidence('missing', 'table-dormant')
    addr_set = next((item for item in snapshot.sets if item.name == action.addr_set), None)
    if addr_set is None:
        return NftEvidence('missing', 'set-absent')
    if addr_set.address_type != ('ipv6_addr' if address.version == 6 else 'ipv4_addr'):
        return NftEvidence('missing', 'set-type-mismatch')
    if not addr_set.supported:
        return NftEvidence('unverifiable', 'unsupported-set-elements')
    if address.compressed not in addr_set.members:
        return NftEvidence('missing', 'ban-entry-absent')
    chain = next((item for item in snapshot.chains if item.name == action.chain), None)
    if chain is None:
        return NftEvidence('missing', 'chain-absent')
    if chain.chain_type != 'filter' or chain.hook != action.chain_hook or not chain.priority_present:
        return NftEvidence('missing', 'chain-not-hooked')
    return _rule_evidence(action, snapshot.rules)


def _rule_evidence(action: NftAction, rules: tuple[NftRule, ...]) -> NftEvidence:
    """A positive source lookup and blocking verdict must belong to the same rule."""
    candidates = [rule for rule in rules if rule.chain == action.chain and action.addr_set in rule.references]
    for rule in candidates:
        if (rule.supported and rule.source_set == action.addr_set and
                rule.ip_version == action.ip_version and rule.verdict == action.verdict):
            return NftEvidence('confirmed', 'entry-observed')
    if any(not rule.supported for rule in rules if rule.chain == action.chain):
        return NftEvidence('unverifiable', 'unsupported-rule-expression')
    referenced = any(rule.source_set == action.addr_set and rule.ip_version == action.ip_version for rule in candidates)
    return NftEvidence('missing', 'blocking-verdict-absent' if referenced else 'rule-reference-absent')
