"""Deterministic full-period concentration snapshots using injected local enrichment."""
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Callable

from offenders_filter import matches_terms, normalize_query
from offenders_geoip import Enrichment, LookupResult
from offenders_report import Report


@dataclass(frozen=True)
class AggregateRow:
    """Full bucket counts and loaded terms; visibility never changes these counts."""

    identity: tuple[str, str]
    bans: int
    distinct_ips: int
    value: str
    organization: str
    terms: tuple[str, ...]


@dataclass(frozen=True)
class AggregateSnapshot:
    """Both views share one acquisition pass for a committed report."""

    asn: tuple[AggregateRow, ...]
    country: tuple[AggregateRow, ...]


def display(result: LookupResult, *, asn: bool = False) -> str:
    """Format independent database states without collapsing healthy absence."""
    if result.state != "mapped":
        return result.state.title()
    value = result.value or ""
    return f"AS{value}" if asn and value.isdigit() else value


def _rows(kind: str, counts: Counter, jails: dict, facts: dict) -> tuple[AggregateRow, ...]:
    """Group each unique address once, weighting it by all its repeated events."""
    buckets = defaultdict(list)
    for ip, enrichment in facts.items():
        result = getattr(enrichment, kind)
        buckets[(result.state, result.value if result.state == "mapped" else "")].append(ip)
    rows = []
    for identity, ips in buckets.items():
        result = getattr(facts[ips[0]], kind)
        value = display(result, asn=kind == "asn")
        organizations = sorted({facts[ip].asn.organization for ip in ips
                                if facts[ip].asn.organization})
        organization = ""
        if kind == "asn" and result.state == "mapped":
            organization = organizations[0] if len(organizations) == 1 else "Multiple" if organizations else ""
        terms = {value, organization}
        for ip in ips:
            enrichment = facts[ip]
            terms.update((ip, *jails[ip], display(enrichment.country),
                          display(enrichment.asn, asn=True), enrichment.asn.value or "",
                          enrichment.asn.organization or ""))
        rows.append(AggregateRow(identity, sum(counts[ip] for ip in ips), len(ips),
                                 value, organization, tuple(sorted(terms))))
    return tuple(sorted(rows, key=lambda row: (-row.bans, -row.distinct_ips, row.identity)))


def aggregate_report(report: Report, lookup: Callable[[str], Enrichment]) -> AggregateSnapshot:
    """Reuse structured top facts, then look up each remaining unique IP exactly once."""
    counts = Counter(event.ip for event in report.events)
    jails = defaultdict(set)
    for event in report.events:
        jails[event.ip].add(event.jail)
    loaded = {row.ip: row.enrichment for row in report.top_offenders if row.enrichment is not None}
    facts = {ip: loaded[ip] if ip in loaded else lookup(ip) for ip in sorted(counts)}
    return AggregateSnapshot(_rows("asn", counts, jails, facts),
                             _rows("country", counts, jails, facts))


def filter_aggregates(rows: tuple[AggregateRow, ...], query: str) -> tuple[AggregateRow, ...]:
    """Hide whole buckets using the same literal Unicode semantics as IP mode."""
    query = normalize_query(query)
    return tuple(row for row in rows if matches_terms(query, row.terms))
