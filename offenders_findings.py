"""Pure candidate policy over same-source pattern and coverage snapshots."""
from __future__ import annotations

from dataclasses import dataclass

from offenders_coverage import CoverageInventory, CoverageTarget, STOCK_FAMILIES
from offenders_patterns import COUNT_NOTE, PatternGroup, PatternInventory
from offenders_sources import LogSource

# Exact semantic compatibility; family membership alone never proves relevance.
COMPATIBILITY = {
    **dict.fromkeys(("ssh_failed_password", "ssh_invalid_user", "ssh_authentication_failure"), "sshd"),
    "dovecot_authentication_failure": "dovecot",
    "vsftpd_login_failure": "vsftpd",
    "proftpd_login_failure": "proftpd",
    "proftpd_root_login": "proftpd",
    "pure-ftpd_authentication_failure": "pure-ftpd",
    "nginx_http_authentication_failure": "nginx-http-auth",
    "apache_http_authentication_failure": "apache-auth",
    **{f"{family}:path_probe:{category}": f"{family}-botsearch"
       for family in ("nginx", "apache") for category in ("database_admin", "cgi_script")},
}
ACTIVE_STATES = frozenset(("listening_non_loopback", "listening_loopback",
                           "active_no_matching_listener_observed", "active_listener_unknown"))
CANDIDATES = frozenset(("existing_disabled_candidate", "enabled_tuning_question", "custom_gap_candidate"))
BASE_REASON = "at least 3 recognized records and at least 1 global source IP"


@dataclass(frozen=True, order=True)
class FilterMatch:
    """Resolved jail/filter identity with factual relevance, pending validation."""

    name: str
    filter_stem: str
    reasons: tuple[str, ...]
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class FindingDecision:
    """One outcome retaining exact counts, times, examples and coverage provenance.

    The exact group owns canonical identity and all measured pattern facts.
    Coverage targets retain every contributing classification and alias evidence.
    Candidate classes are review facts, never instructions to change a jail.
    """

    classification: str
    group: PatternGroup
    service_states: tuple[str, ...]
    running_filters: tuple[FilterMatch, ...]
    disabled_candidates: tuple[FilterMatch, ...]
    coverage_targets: tuple[CoverageTarget, ...]
    reason: str
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class FindingInventory:
    """Exact inputs, one ordered decision per group, and its candidate subset."""

    pattern_inventory: PatternInventory
    coverage_inventory: CoverageInventory
    decisions: tuple[FindingDecision, ...]
    findings: tuple[FindingDecision, ...]


def _source_key(source: LogSource) -> tuple[str, str]:
    """Canonicalize supplied strings without resolving paths on the host."""
    identity = source.resolved_path or source.identity if source.kind == "file" else source.identity
    return source.kind, identity


def _bounded(messages) -> tuple[str, ...]:
    """Deterministically bound unique limitations and signal any truncation."""
    originals = sorted(set(messages))
    clipped = sorted({text.encode("utf-8", errors="replace")[:300].decode("utf-8", errors="ignore")
                      for text in originals})
    if clipped != originals or len(clipped) > 32:
        return tuple(clipped[:31]) + ("limitations capped (count or UTF-8 byte limit)",)
    return tuple(clipped)


def _compatible(group: PatternGroup, stem: str) -> bool:
    """Only the explicit authentication kind or full path signature can match."""
    key = group.signature if group.pattern_kind == "path_probe" else group.pattern_kind
    return COMPATIBILITY.get(key) == stem


def _running(group, targets, static, notes):
    """Split source-monitoring jails into compatible, other-family, or unknown."""
    definitions = {row.name: row for row in static.jails}
    matches, unknown = [], False
    for name in sorted({name for target in targets for name in target.running_jails}):
        jail = definitions.get(name)
        stem = jail.filter_stem if jail and static.jail_reads_complete else None
        if jail:
            notes.extend(jail.limitations)
        if stem and _compatible(group, stem):
            matches.append(FilterMatch(name, stem, ("exact pattern/filter compatibility",)))
        elif not stem or STOCK_FAMILIES.get(stem, group.family) == group.family:
            unknown = True
            notes.append(f"{name}: running filter pattern relevance unknown")
    if matches:
        notes.append("enabled-source monitoring does not prove every observed record matched the filter")
    return tuple(matches), unknown


def _disabled(group, targets, static, notes):
    """Narrow upstream disabled facts without inferring relevance from names."""
    definitions = {row.name: row for row in static.jails}
    evidence = {}
    for target in targets:
        for match in target.disabled_definitions:
            evidence.setdefault(match.name, []).append(match)
    retained, unresolved = [], False
    for name, matches in sorted(evidence.items()):
        jail = definitions.get(name)
        if not jail or not static.jail_reads_complete or not jail.filter_stem:
            unresolved = True
            notes.append(f"{name}: disabled filter identity unresolved")
            continue
        stem = jail.filter_stem
        reasons = tuple(sorted({match.reason for match in matches}))
        limits = [note for match in matches for note in match.limitations]
        limits.extend(jail.limitations)
        partial = (group.signature == f"{group.family}:path_probe:wordpress_auth"
                   and stem == f"{group.family}-botsearch")
        concrete = bool(set(reasons) & {"literal configured file pattern", "exact filter journal unit"})
        if partial:
            limits.append("WordPress botsearch compatibility is partial/ambiguous")
        elif stem not in STOCK_FAMILIES and concrete:
            limits.append("disabled custom filter pattern matching is unvalidated")
        elif not _compatible(group, stem):
            continue
        limits.append("disabled candidate requires concrete filter validation before suitability review")
        retained.append(FilterMatch(name, stem, reasons, _bounded(limits)))
        notes.extend(limits)
    return tuple(retained), unresolved


def _gate(group, analyses, states, targets):
    """Validate evidence identity and service eligibility before count rules."""
    if not analyses or any(row.state not in ("analyzed", "partial") for row in analyses):
        return "insufficient_evidence", "matching supported source analysis unavailable"
    if not targets:
        return "insufficient_evidence", "no matching canonical coverage target"
    if not states or any(state not in ACTIVE_STATES | {"installed_inactive"} for state in states):
        return "insufficient_evidence", "service state missing or unknown"
    if set(states) == {"installed_inactive"}:
        return "inactive_service", "all matching service associations are installed inactive"
    if group.event_count < 3:
        return "below_recurrence_threshold", "fewer than 3 recognized records"
    if group.global_source_ip_count < 1:
        return "non_global_only", "no observed global source IP"
    return None


def _policy(group, targets, coverage, notes):
    """Apply enabled-first precedence; ambiguous running protection blocks gaps."""
    running, unknown = _running(group, targets, coverage.static, notes)
    disabled, unresolved = _disabled(group, targets, coverage.static, notes)
    if running:
        strong = (group.event_count >= 10 and group.global_source_ip_count >= 2) or group.event_count >= 20
        if strong:
            outcome = ("enabled_tuning_question", BASE_REASON + "; at least 10/2 or 20/1 records/global IPs")
        else:
            outcome = ("enabled_relevant_below_tuning_threshold", "compatible enabled coverage; fewer than 10/2 and 20/1 records/global IPs")
    elif unknown:
        outcome = ("insufficient_evidence", "running source jail has unknown pattern relevance")
    elif disabled:
        outcome = ("existing_disabled_candidate", BASE_REASON + "; disabled validation target exists")
    elif unresolved:
        outcome = ("insufficient_evidence", "disabled filter identity unresolved")
    elif any(target.classification == "no_obvious_match" for target in targets):
        outcome = ("custom_gap_candidate", BASE_REASON + "; explicit complete-enough coverage negative")
    else:
        outcome = ("insufficient_evidence", "no trustworthy no_obvious_match coverage negative")
    return outcome, running, disabled


def _decision(group, patterns, coverage):
    """Join aliases once while retaining positive evidence and all provenance."""
    key = group.source_kind, group.source_identity
    analyses = tuple(row for row in patterns.analyses
                     if (row.source_kind, row.source_identity, row.family) == (*key, group.family))
    states = tuple(sorted({association.service_state for source in coverage.source_inventory.sources
                           if _source_key(source) == key for association in source.associations
                           if association.family == group.family}))
    targets = tuple(sorted((row for row in coverage.targets
                            if _source_key(row.source) == key and row.association
                            and row.association.family == group.family), key=repr))
    notes = [COUNT_NOTE, *group.limitations, *patterns.evidence_snapshot.limitations,
             *coverage.static.limitations]
    notes.extend(note for row in analyses for note in row.limitations)
    notes.extend(note for row in targets for note in row.limitations)
    if "listening_loopback" in states:
        notes.append("source listens loopback only; listener scope does not establish Internet reachability")
    if "active_listener_unknown" in states:
        notes.append("listener ownership is unknown")
    if group.timestamp_basis != "utc":
        notes.append("local-wall/unknown timestamps do not enforce the exact UTC lookback")
    if patterns.evidence_snapshot.truncated:
        notes.append("evidence/history was truncated")
    outcome = _gate(group, analyses, states, targets)
    running, disabled = (), ()
    if outcome is None:
        outcome, running, disabled = _policy(group, targets, coverage, notes)
    return FindingDecision(outcome[0], group, states, running, disabled, targets, outcome[1], _bounded(notes))


def build_findings(pattern_inventory: PatternInventory, coverage_inventory: CoverageInventory) -> FindingInventory:
    """Correlate supplied objects only; reject separately acquired source snapshots."""
    if pattern_inventory.evidence_snapshot.source_inventory is not coverage_inventory.source_inventory:
        raise ValueError("Pattern and coverage inventories must retain the exact same LogSourceInventory object")
    groups = sorted(pattern_inventory.groups, key=lambda row: (
        row.family, row.source_kind, row.source_identity, row.pattern_kind, row.signature, row.timestamp_basis))
    decisions = tuple(_decision(group, pattern_inventory, coverage_inventory) for group in groups)
    return FindingInventory(pattern_inventory, coverage_inventory, decisions,
                            tuple(row for row in decisions if row.classification in CANDIDATES))
