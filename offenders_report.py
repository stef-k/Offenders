"""Read rotated Fail2Ban logs and derive GeoIP-enriched dashboard reports."""
from __future__ import annotations

import datetime as dt
import glob
import gzip
import ipaddress
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Tuple

from offenders_geoip import DatabaseHealth, Enrichment, geoip

from offenders_fail2ban import JailStatus, get_jail_list, get_jail_status

# =========================
# Config
# =========================

LOG_CURRENT = "/var/log/fail2ban.log"
LOG_ROTATED = "/var/log/fail2ban.log.1"
LOG_GZ_GLOB = "/var/log/fail2ban.log.*.gz"

TOP_COUNT = 20
LOOKBACK_DAYS = 7  # 0 => all available
IGNORE_PRIVATE = True  # skip RFC1918/private IPs (and IPv6 equivalents)

# Match the token after "Ban" (IPv4 or IPv6-ish), then validate with ipaddress.ip_address()
BAN_IP_RE = re.compile(r"\bBan\s+([0-9A-Fa-f:.]+)\b")

# Tolerant helpers for the "Last bans" table
BAN_LINE_TIME_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})(?:,\d+)?\s+"
)
BRACKET_RE = re.compile(r"\[([^\]]+)\]")

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
    generated_at: dt.datetime
    cutoff_date: Optional[dt.date]  # None if LOOKBACK_DAYS == 0
    total_bans: int
    ban_lines: List[str]  # filtered Ban lines (selected period)
    top_offenders: List[Offender]
    jail_statuses: List[JailStatus]
    last_10_bans: List[str]
    geoip_health: dict[str, DatabaseHealth] = field(default_factory=dict)

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


# =========================
# Log reading
# =========================


def _gz_rot_num(path: str) -> int:
    m = re.search(r"\.(\d+)\.gz$", path)
    return int(m.group(1)) if m else 0


def _log_files() -> List[str]:
    files: List[str] = []

    gz_files = glob.glob(LOG_GZ_GLOB)
    # fail2ban.log.2.gz is newer than .3.gz, so sort descending so oldest comes first
    gz_files = sorted(gz_files, key=_gz_rot_num, reverse=True)
    files.extend(gz_files)

    if os.path.isfile(LOG_ROTATED):
        files.append(LOG_ROTATED)

    if os.path.isfile(LOG_CURRENT):
        files.append(LOG_CURRENT)

    return files


def _iter_lines(path: str) -> Iterable[str]:
    if path.endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            yield from f
    else:
        with open(path, "rt", encoding="utf-8", errors="replace") as f:
            yield from f


def iter_unified_log_stream() -> Iterable[str]:
    for path in _log_files():
        try:
            yield from _iter_lines(path)
        except FileNotFoundError:
            continue


# =========================
# Filtering Ban lines
# =========================


def parse_log_date(line: str) -> Optional[dt.date]:
    parts = line.split()
    if not parts:
        return None
    try:
        return dt.date.fromisoformat(parts[0])
    except ValueError:
        return None


def is_real_ban_line(line: str) -> bool:
    m = BAN_IP_RE.search(line)
    if not m:
        return False
    token = m.group(1)
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


def collect_ban_lines(lookback_days: int) -> Tuple[List[str], Optional[dt.date]]:
    ban_lines: List[str] = []

    cutoff_date: Optional[dt.date] = None
    if lookback_days and lookback_days > 0:
        cutoff_date = dt.datetime.now().date() - dt.timedelta(days=lookback_days)

    for line in iter_unified_log_stream():
        if not is_real_ban_line(line):
            continue

        if cutoff_date is not None:
            d = parse_log_date(line)
            if d is None or d < cutoff_date:
                continue

        ban_lines.append(line.rstrip("\n"))

    return ban_lines, cutoff_date


def extract_ips(ban_lines: Iterable[str]) -> List[str]:
    ips: List[str] = []
    for line in ban_lines:
        m = BAN_IP_RE.search(line)
        if not m:
            continue
        token = m.group(1)
        try:
            ips.append(ipaddress.ip_address(token).compressed)
        except ValueError:
            continue
    return ips


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
    lookback_days: int = LOOKBACK_DAYS,
    ignore_private: bool = IGNORE_PRIVATE,
) -> Report:
    if not (os.path.isfile(LOG_CURRENT) or os.path.isfile(LOG_ROTATED)):
        raise FileNotFoundError(
            f"No Fail2Ban logs found at {LOG_CURRENT} or {LOG_ROTATED}"
        )

    ban_lines, cutoff_date = collect_ban_lines(lookback_days)

    jail_statuses = [get_jail_status(jail) for jail in get_jail_list()]

    geoip_health = geoip.refresh()

    if not ban_lines:
        return Report(
            generated_at=dt.datetime.now(),
            cutoff_date=cutoff_date,
            total_bans=0,
            ban_lines=[],
            top_offenders=[],
            jail_statuses=jail_statuses,
            last_10_bans=[],
            geoip_health=geoip_health,
        )

    ips = extract_ips(ban_lines)
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

    last10 = ban_lines[-10:] if len(ban_lines) >= 10 else ban_lines[:]

    return Report(
        generated_at=dt.datetime.now(),
        cutoff_date=cutoff_date,
        total_bans=len(ban_lines),
        ban_lines=ban_lines,
        top_offenders=offenders,
        jail_statuses=jail_statuses,
        last_10_bans=last10,
        geoip_health=geoip.health(),
    )


def _parse_ban_line_for_table(line: str) -> Tuple[str, str, str, str]:
    """
    Returns: (date, time, jail, ip)
    Always returns a row (never filters out lines here).
    """
    date = ""
    time = ""
    jail = ""
    ip = ""

    mt = BAN_LINE_TIME_RE.search(line)
    if mt:
        date = mt.group("date")
        time = mt.group("time")

    brackets = BRACKET_RE.findall(line)
    if brackets:
        for token in brackets:
            token = token.strip()
            if not token:
                continue
            if token.isdigit():
                continue  # skip PID like [996]

            # skip logger-ish tokens; keep actual jails
            low = token.lower()
            if low.startswith("fail2ban."):
                continue

            jail = token
            break

    mi = BAN_IP_RE.search(line)
    if mi:
        token = mi.group(1)
        try:
            ip = ipaddress.ip_address(token).compressed
        except ValueError:
            ip = ""

    return (date, time, jail, ip)
