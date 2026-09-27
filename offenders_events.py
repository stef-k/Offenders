"""Acquire normalized Fail2Ban history from plain and rotated gzip logs.

Timestamps are naive local wall-clock values: source lines have no UTC offset,
so their inherent DST ambiguity cannot be recovered. Equal timestamps retain
source encounter order, including repeated records.
"""
from __future__ import annotations

import datetime as dt
import glob
import gzip
import ipaddress
import os
import re
from dataclasses import dataclass
from typing import Iterable


# Require the complete timestamp and address token, never a valid prefix.
_TIMESTAMP_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:[,.]\d{1,6})?)\s+"
)
_BAN_RE = re.compile(r"\bBan\s+(\S+)")
_BRACKET_RE = re.compile(r"\[([^\]]*)\]")


@dataclass(frozen=True)
class BanEvent:
    """A complete historical ban; raw text supports the legacy report view."""

    timestamp: dt.datetime
    jail: str
    ip: str
    raw_line: str


def parse_ban_event(line: str) -> BanEvent | None:
    """Skip malformed/non-ban records and normalize one unambiguous jail/IP."""
    timestamp = _TIMESTAMP_RE.match(line)
    ban = _BAN_RE.search(line)
    if timestamp is None or ban is None:
        return None
    jails = [
        token.strip() for token in _BRACKET_RE.findall(line[:ban.start()])
        if token.strip() and not token.strip().isdigit()
        and not token.strip().lower().startswith("fail2ban.")
    ]
    if len(jails) != 1:
        return None
    try:
        parsed_time = dt.datetime.fromisoformat(timestamp.group(1).replace(",", "."))
        address = ipaddress.ip_address(ban.group(1))
    except ValueError:
        return None
    return BanEvent(parsed_time, jails[0], address.compressed, line.rstrip("\n"))


def _gz_rot_num(path: str) -> int:
    """Numeric rotations descend from oldest to newest."""
    match = re.search(r"\.(\d+)\.gz$", path)
    return int(match.group(1)) if match else 0


def _iter_lines(path: str) -> Iterable[str]:
    """Decode log records tolerantly while preserving source I/O failures."""
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as stream:
        yield from stream


def collect_ban_events(current: str, rotated: str, gz_glob: str) -> list[BanEvent]:
    """Read available sources and stably sort complete events chronologically.

    A plain current or rotated source remains required. Disappearing rotations
    are harmless; other I/O failures propagate to the report's degraded state.
    """
    if not (os.path.isfile(current) or os.path.isfile(rotated)):
        raise FileNotFoundError(f"No Fail2Ban logs found at {current} or {rotated}")
    files = sorted(glob.glob(gz_glob), key=lambda path: (-_gz_rot_num(path), path))
    files.extend(path for path in (rotated, current) if os.path.isfile(path))
    events = []
    for path in files:
        try:
            for line in _iter_lines(path):
                event = parse_ban_event(line)
                if event is not None:
                    events.append(event)
        except FileNotFoundError:
            continue
    return sorted(events, key=lambda event: event.timestamp)
