"""Read rotated Fail2Ban logs and derive GeoIP-enriched dashboard reports."""
from __future__ import annotations

import datetime as dt
import ipaddress
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Tuple

from offenders_events import BanEvent, collect_ban_events
from offenders_geoip import DatabaseHealth, Enrichment, geoip

from offenders_fail2ban import JailStatus, get_jail_list, get_jail_status

# =========================
# Config
# =========================

LOG_CURRENT = "/var/log/fail2ban.log"
LOG_ROTATED = "/var/log/fail2ban.log.1"
LOG_GZ_GLOB = "/var/log/fail2ban.log.*.gz"

TOP_COUNT = 20
# Insertion order is the dashboard cycle order; keys also serve as compact labels.
PERIODS = {
    "1h": dt.timedelta(hours=1),
    "24h": dt.timedelta(hours=24),
    "7d": dt.timedelta(hours=168),
    "30d": dt.timedelta(days=30),
    "all": None,
}
DEFAULT_PERIOD = "7d"
IGNORE_PRIVATE = True  # skip RFC1918/private IPs (and IPv6 equivalents)

# =========================
# Models
# =========================


@dataclass(frozen=True)
class Offender:
    ip: str
    count: int
    country: str
    asn: str
    asn_org: str
    enrichment: Enrichment | None = None


@dataclass(frozen=True)
class Report:
    """Selected parsed history, enriched rankings, and independent live status."""

    generated_at: dt.datetime
    period: str
    window_start: Optional[dt.datetime]  # None for all available events
    events: List[BanEvent]  # chronological events in the selected period
    top_offenders: List[Offender]
    jail_statuses: List[JailStatus]
    geoip_health: dict[str, DatabaseHealth] = field(default_factory=dict)

    @property
    def total_bans(self) -> int:
        """Count all selected events, including private addresses."""
        return len(self.events)

    @property
    def ban_lines(self) -> List[str]:
        """Expose legacy raw lines only as a derived compatibility view."""
        return [event.raw_line for event in self.events]

    @property
    def last_10_bans(self) -> List[BanEvent]:
        """Use the latest ten parsed events in chronological order."""
        return self.events[-10:]

    @property
    def jail_list(self) -> List[str]:
        """Keep the daemon's jail order for the dashboard."""
        return [status.name for status in self.jail_statuses]

    @property
    def bans_per_jail(self) -> List[Tuple[str, int]]:
        """Retain the dashboard's descending ban-count presentation."""
        return sorted(
            [(status.name, status.currently_banned) for status in self.jail_statuses],
            key=lambda item: item[1], reverse=True,
        )


def filter_private_ips(ips: Iterable[str]) -> List[str]:
    out: List[str] = []
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue

        if addr.is_private or addr.is_loopback or addr.is_link_local:
            continue

        out.append(ip)
    return out


# =========================
# Main report builder
# =========================


def build_report(
    top_count: int = TOP_COUNT,
    period: str = DEFAULT_PERIOD,
    ignore_private: bool = IGNORE_PRIVATE,
) -> Report:
    """Derive counts and enrichment from the selected normalized history."""
    duration = PERIODS[period]
    now = dt.datetime.now()
    window_start = now - duration if duration is not None else None
    events = collect_ban_events(LOG_CURRENT, LOG_ROTATED, LOG_GZ_GLOB)
    if window_start is not None:
        events = [event for event in events if window_start <= event.timestamp <= now]

    jail_statuses = [get_jail_status(jail) for jail in get_jail_list()]

    geoip_health = geoip.refresh()

    ips = [event.ip for event in events]
    if ignore_private:
        ips = filter_private_ips(ips)

    counts = Counter(ips)
    top = counts.most_common(top_count)

    offenders: List[Offender] = []
    for ip, c in top:
        enrichment = geoip.lookup(ip)
        offenders.append(
            Offender(
                ip=ip,
                count=c,
                country=enrichment.country.value or "Unknown",
                asn=enrichment.asn.value or "No ASN",
                asn_org=enrichment.asn.organization or "No ASN org",
                enrichment=enrichment,
            )
        )

    return Report(
        generated_at=now,
        period=period,
        window_start=window_start,
        events=events,
        top_offenders=offenders,
        jail_statuses=jail_statuses,
        geoip_health=geoip.health() if events else geoip_health,
    )
