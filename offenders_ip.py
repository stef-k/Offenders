"""Project one selected IP from a successful report, without acquiring new facts."""
from __future__ import annotations

import datetime as dt
import ipaddress
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass

from offenders_events import BanEvent
from offenders_geoip import Enrichment, geoip
from offenders_report import Report


@dataclass(frozen=True)
class IPProjection:
    """Immutable period history and separate live membership for one report."""

    ip: str
    period: str
    generated_at: dt.datetime
    total_bans: int
    first_seen: dt.datetime | None
    last_seen: dt.datetime | None
    distinct_jail_count: int
    jail_counts: tuple[tuple[str, int], ...]
    recent_events: tuple[BanEvent, ...]
    currently_banned: bool
    current_jails: tuple[str, ...]
    enrichment: Enrichment


def project_ip(
    report: Report, ip: str, *, lookup: Callable[[str], Enrichment] = geoip.lookup,
) -> IPProjection:
    """Derive history/live facts only from the report; enrich locally if needed.

    Report events already contain normalized addresses and the committed period.
    Stable newest-first sorting retains encounter order for equal timestamps.
    Current membership uses address lists, independently of non-atomic counters.
    Callers integrating a UI must run this local MMDB work off its event loop.
    Invalid selected addresses raise ValueError.
    """
    normalized = ipaddress.ip_address(ip).compressed
    events = sorted(
        (event for event in report.events if event.ip == normalized),
        key=lambda event: event.timestamp, reverse=True,
    )
    counts = Counter(event.jail for event in events)
    jail_counts = tuple(sorted(counts.items(), key=lambda item: (-item[1], item[0])))
    current_jails = tuple(
        status.name for status in report.jail_statuses
        if any(ipaddress.ip_address(address).compressed == normalized
               for address in status.banned_ips)
    )
    enrichment = next(
        (offender.enrichment for offender in report.top_offenders
         if offender.ip == normalized and offender.enrichment is not None),
        None,
    )
    if enrichment is None:
        enrichment = lookup(normalized)
    return IPProjection(
        ip=normalized, period=report.period, generated_at=report.generated_at,
        total_bans=len(events), first_seen=events[-1].timestamp if events else None,
        last_seen=events[0].timestamp if events else None,
        distinct_jail_count=len(counts), jail_counts=jail_counts,
        recent_events=tuple(events[:10]), currently_banned=bool(current_jails),
        current_jails=current_jails, enrichment=enrichment,
    )
