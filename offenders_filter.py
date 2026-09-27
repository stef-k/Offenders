"""Pure visibility projection over already loaded dashboard report facts."""
from dataclasses import dataclass

from offenders_events import BanEvent
from offenders_report import Offender, Report


@dataclass(frozen=True)
class FilteredRows:
    """Original rows in source order, with the normalized active query."""

    query: str
    top_offenders: tuple[Offender, ...]
    last_bans: tuple[BanEvent, ...]


def filter_rows(report: Report, query: str) -> FilteredRows:
    """Match individual loaded fields without enrichment or count recomputation."""
    query = normalize_query(query)
    if not query:
        return FilteredRows(query, tuple(report.top_offenders), tuple(report.last_10_bans))
    enrichment = {
        row.ip: (row.country, row.asn, f"AS{row.asn}" if row.asn.isdigit() else row.asn,
                 row.asn_org)
        for row in report.top_offenders
    }
    jails: dict[str, set[str]] = {ip: set() for ip in enrichment}
    for event in report.events:
        if event.ip in jails:
            jails[event.ip].add(event.jail)

    return FilteredRows(
        query,
        tuple(row for row in report.top_offenders
              if matches_terms(query, (row.ip, *enrichment[row.ip], *jails[row.ip]))),
        tuple(event for event in report.last_10_bans
              if matches_terms(query, (event.ip, event.jail, *enrichment.get(event.ip, ())))),
    )


def normalize_query(query: str) -> str:
    """Trim and casefold the shared literal visibility query."""
    return query.strip().casefold()


def matches_terms(query: str, terms: tuple[str, ...]) -> bool:
    """Match a normalized query against individual already-loaded fields."""
    return not query or any(query in term.casefold() for term in terms)
