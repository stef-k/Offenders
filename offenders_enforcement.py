"""Manual, read-only Fail2Ban/firewall bracketing over the reviewed backends."""
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import ipaddress

import offenders_fail2ban as f2b
import offenders_host as host
import offenders_nftables as nft
import offenders_iptables as ipt
import offenders_ufw as ufw

READ_ERRORS = (f2b.Fail2BanCommandError, f2b.Fail2BanParseError)


@dataclass(frozen=True)
class EnforcementRow:
    """One immutable action/IP fact, or explicit jail/IP-level non-action fact."""

    jail: str
    ip: str = ''
    action: str = ''
    backend: str = ''
    outcome: str = 'unverifiable'
    reason: str = ''
    backend_reason: str = ''
    unclassified_actions: tuple[str, ...] = ()
    unavailable_actions: tuple[str, ...] = ()
    managed_rule: bool | None = None
    live_rule: bool | None = None
    connection_termination: str = 'not-requested'

    @property
    def identity(self) -> tuple[str, str, str, str]:
        """Keep supported actions distinct without parsing rendered cells."""
        return self.jail, self.ip, self.action, self.backend


@dataclass(frozen=True)
class EnforcementResult:
    """Bounded final facts only; no action programs or raw firewall snapshots."""

    rows: tuple[EnforcementRow, ...] = ()
    reason: str = ''
    collected_at: datetime | None = None


@dataclass(frozen=True)
class FamilyAction:
    """Characterize one action/family without retaining its command program."""

    family: str
    backend: str = ''
    descriptor: nft.NftAction | ipt.IptablesAction | ufw.UfwAction | None = None
    reason: str = ''


@dataclass(frozen=True)
class ActionObservation:
    """Retain identity, exact queried-fact hash, and family characterization."""

    name: str
    fingerprint: str
    families: tuple[FamilyAction, ...]


@dataclass(frozen=True)
class JailObservation:
    """Ephemeral bracket state; an error never means an empty banned-IP set."""

    jail: str
    ips: frozenset[str] = frozenset()
    actions: tuple[ActionObservation, ...] = ()
    fingerprint: str = ''
    reason: str = ''


def _characterize(properties: dict[str, str], family: str) -> FamilyAction:
    """Exactly one reviewed descriptor qualifies; ambiguous matches fail closed."""
    matches = []
    unavailable = False
    for backend, classifier in (('nftables', nft.classify_nft_action),
                                ('iptables', ipt.classify_iptables_action),
                                ('ufw', ufw.classify_ufw_action)):
        try:
            descriptor = classifier(properties, family=family)
            if descriptor is not None:
                matches.append((backend, descriptor))
        except f2b.Fail2BanParseError:
            # Other families need not expose this classifier's static facts.
            unavailable = True
    if len(matches) > 1:
        return FamilyAction(family, reason='ambiguous-action')
    if matches:
        return FamilyAction(family, *matches[0])
    return FamilyAction(family, reason='action-metadata-unavailable' if unavailable else 'unsupported-action')


def _observe_jail(jail: str) -> JailObservation:
    """Use the same bounded current-ban/action path on both sides of the bracket."""
    if not f2b.ACTION_ID.fullmatch(jail):
        bounded = ''.join(c for c in jail[:128] if c.isprintable())
        return JailObservation(bounded, reason='unsafe-jail-identity')
    try:
        ips = frozenset(f2b.get_jail_core_status(jail).banned_ips)
    except READ_ERRORS:
        return JailObservation(jail, reason='jail-state-unavailable')
    if not ips:
        return JailObservation(jail)
    families = tuple(sorted({'inet6' if ipaddress.ip_address(ip).version == 6 else 'inet4' for ip in ips}))
    try:
        names = f2b.get_jail_actions(jail)
    except READ_ERRORS:
        return JailObservation(jail, ips, reason='action-list-unavailable')
    observations, facts = [], {}
    for name in names:
        properties = {}
        try:
            advertised = f2b.get_action_properties(jail, name)
            for prop in sorted((set(advertised) & f2b.ACTION_PROPERTIES) - {'actionstart'}):
                properties[prop] = f2b.get_action_property(jail, name, prop)
            # Only the exact stock config-reader sentinel needs raw start facts.
            if properties.get('chain') == '<known/chain>' and 'actionstart' in advertised:
                properties['actionstart'] = f2b.get_action_property(jail, name, 'actionstart')
            if 'actionban' not in properties:
                raise f2b.Fail2BanParseError('Action ban property unavailable')
            characterized = tuple(_characterize(properties, family) for family in families)
        except READ_ERRORS:
            characterized = tuple(FamilyAction(family, reason='action-metadata-unavailable') for family in families)
        facts[name] = properties
        observations.append(ActionObservation(name, f2b.action_fingerprint(jail, {name: properties}), characterized))
    return JailObservation(jail, ips, tuple(observations), f2b.action_fingerprint(jail, facts))


def _family(action: ActionObservation, ip: str) -> FamilyAction:
    """Select a characterization by the opening address family."""
    family = 'inet6' if ipaddress.ip_address(ip).version == 6 else 'inet4'
    return next(item for item in action.families if item.family == family)


def _opening_rows(jail: JailObservation) -> tuple[EnforcementRow, ...]:
    """Retain supported rows and sibling detail; never invent an action identity."""
    if jail.reason:
        return (EnforcementRow(jail.jail, reason=jail.reason),)
    if not jail.ips:
        return (EnforcementRow(jail.jail, outcome='no-current-bans', reason='no-current-bans'),)
    rows = []
    for ip in sorted(jail.ips):
        characterized = [(action.name, _family(action, ip)) for action in jail.actions]
        unclassified = tuple(name for name, item in characterized if item.reason == 'unsupported-action')
        unavailable = tuple(name for name, item in characterized if item.reason and item.reason != 'unsupported-action')
        supported = [(name, item) for name, item in characterized if item.descriptor is not None]
        detail = dict(unclassified_actions=unclassified, unavailable_actions=unavailable)
        if supported:
            rows.extend(EnforcementRow(jail.jail, ip, name, item.backend, **detail) for name, item in supported)
        else:
            reason = 'unsupported-action'
            if unavailable:
                reason = 'ambiguous-action' if any(item.reason == 'ambiguous-action' for _, item in characterized) else 'action-metadata-unavailable'
            rows.append(EnforcementRow(jail.jail, ip, outcome='unverifiable' if unavailable else 'unsupported-action', reason=reason, **detail))
    return tuple(rows)


def _acquire(jails: tuple[JailObservation, ...]) -> dict[tuple[str, str, str, str], nft.NftEvidence | ipt.IptablesEvidence | ufw.UfwEvidence]:
    """Batch once per backend; reviewed readers own table/save-family deduplication."""
    supported = [(jail, action, item) for jail in jails for action in jail.actions
                 for item in action.families if item.descriptor is not None]
    nft_actions = [item.descriptor for _, _, item in supported if item.backend == 'nftables']
    ipt_actions = [item.descriptor for _, _, item in supported if item.backend == 'iptables']
    ufw_actions = [item.descriptor for _, _, item in supported if item.backend == 'ufw']
    nft_views = nft.read_nft_tables(nft_actions) if nft_actions else {}
    ipt_views = ipt.read_iptables_saves(ipt_actions) if ipt_actions else {}
    if ufw_actions:
        ufw_status, ufw_added = ufw.read_ufw_status(), ufw.read_ufw_added()
        ufw_views = ufw.read_ufw_saves(ufw_actions)
    evidence = {}
    for jail, action, item in supported:
        descriptor = item.descriptor
        for ip in sorted(jail.ips):
            if _family(action, ip) != item:
                continue
            if item.backend == 'nftables':
                result = nft.verify_nft_ban(descriptor, ip, nft_views[(descriptor.table_family, descriptor.table)])
            elif item.backend == 'iptables':
                result = ipt.verify_iptables_ban(descriptor, ip, ipt_views[descriptor.save_binary])
            else:
                result = ufw.verify_ufw_ban(descriptor, ip, ufw_status, ufw_added, ufw_views[descriptor.ip_version])
            evidence[(jail.jail, ip, action.name, item.backend)] = result
    return evidence


def _bracket_reason(row: EnforcementRow, opening: JailObservation, closing: JailObservation,
                    before_ns: host.NetworkNamespaceIdentity | None,
                    after_ns: host.NetworkNamespaceIdentity | None) -> tuple[str, str]:
    """Unreadability precedes change; namespace proof applies only to backend facts."""
    if row.backend and after_ns.state == host.NamespaceState.UNAVAILABLE:
        return 'unverifiable', 'closing-namespace-unavailable'
    if closing.reason and closing.reason != 'jail-disappeared':
        return 'unverifiable', 'closing-state-unavailable'
    if closing.reason == 'jail-disappeared':
        return 'changed-during-check', 'jail-disappeared'
    if not closing.ips:
        return 'changed-during-check', 'banned-ips-changed'
    family = 'inet6' if ':' in row.ip else 'inet4'
    if not row.backend and any(item.reason in ('action-metadata-unavailable', 'ambiguous-action')
                               for action in closing.actions for item in action.families if item.family == family):
        return 'unverifiable', 'closing-action-unavailable'
    if {a.name for a in opening.actions} != {a.name for a in closing.actions}:
        return 'changed-during-check', 'action-identities-changed'
    before, after = opening.fingerprint, closing.fingerprint
    if row.backend:
        before = next(a for a in opening.actions if a.name == row.action)
        after = next(a for a in closing.actions if a.name == row.action)
        # A removed address family itself is readable membership-change evidence.
        selected = next((a for a in after.families if a.family == family), None)
        if selected is not None and selected.reason in ('action-metadata-unavailable', 'ambiguous-action'):
            return 'unverifiable', 'closing-action-unavailable'
    if opening.ips != closing.ips:
        return 'changed-during-check', 'banned-ips-changed'
    if row.backend and before_ns != after_ns:
        return 'changed-during-check', 'daemon-namespace-changed'
    complete = all(item.reason not in ('action-metadata-unavailable', 'ambiguous-action')
                   for jail in (opening, closing) for action in jail.actions for item in action.families)
    if before != after or complete and opening.fingerprint != closing.fingerprint:
        return 'changed-during-check', 'action-changed'
    return '', ''


def check_enforcement() -> EnforcementResult:
    """Run one fresh manual check; report refresh and export never call this path."""
    try:
        names = f2b.get_jail_list()
    except READ_ERRORS:
        return EnforcementResult(reason='jail-list-unavailable', collected_at=datetime.now(timezone.utc))
    opening = tuple(_observe_jail(name) for name in names)
    rows = tuple(row for jail in opening for row in _opening_rows(jail))
    supported = any(row.backend for row in rows)
    unsupported = any(row.outcome == 'unsupported-action' for row in rows)
    if not supported and not unsupported:
        return EnforcementResult(rows, collected_at=datetime.now(timezone.utc))
    before_ns = host.get_fail2ban_namespace() if supported else None
    if supported and before_ns.state != host.NamespaceState.SAME:
        reason = 'namespace-mismatch' if before_ns.state == host.NamespaceState.DIFFERENT else 'namespace-unavailable'
        rows = tuple(replace(row, outcome='unverifiable', reason=reason) if row.backend else row for row in rows)
        if not unsupported:
            return EnforcementResult(rows, collected_at=datetime.now(timezone.utc))
    evidence = _acquire(opening) if supported and before_ns.state == host.NamespaceState.SAME else {}
    try:
        active = set(f2b.get_jail_list())
        closing = {jail.jail: _observe_jail(jail.jail) if jail.jail in active else
                   JailObservation(jail.jail, reason='jail-disappeared') for jail in opening if jail.ips}
    except READ_ERRORS:
        closing = {jail.jail: JailObservation(jail.jail, reason='jail-list-unavailable') for jail in opening}
    after_ns = host.get_fail2ban_namespace() if evidence else None
    before = {jail.jail: jail for jail in opening}
    final = []
    for row in rows:
        if row.outcome == 'unsupported-action':
            outcome, reason = _bracket_reason(row, before[row.jail], closing[row.jail], None, None)
            final.append(replace(row, outcome=outcome or row.outcome, reason=reason or row.reason))
            continue
        if row.identity not in evidence:
            final.append(row)
            continue
        result = evidence[row.identity]
        outcome, reason = _bracket_reason(row, before[row.jail], closing[row.jail], before_ns, after_ns)
        detail = dict(managed_rule=result.managed_rule, live_rule=result.live_rule,
                      connection_termination=result.connection_termination) if isinstance(result, ufw.UfwEvidence) else {}
        final.append(replace(row, outcome=outcome or result.outcome, reason=reason or result.reason,
                             backend_reason=result.reason, **detail))
    return EnforcementResult(tuple(final), collected_at=datetime.now(timezone.utc))
