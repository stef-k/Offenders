"""Stable spreadsheet-safe CSV bundles from already acquired reports (Linux)."""
import csv
import ctypes
import errno
import os
from pathlib import Path
import tempfile

from offenders_report import PERIODS, Report

# Ordered schema 1 columns are a public compatibility contract.
SCHEMAS = {
    "report.csv": ("schema_version", "period", "generated_at", "window_start", "total_bans",
                   "top_offender_count", "jail_count", "csv_text_policy"),
    "top-offenders.csv": ("rank", "bans", "ip", "country_state", "country", "asn_state", "asn", "organization"),
    "jail-status.csv": ("jail", "currently_failed", "total_failed", "currently_banned", "total_banned",
                        "bantime_seconds", "findtime_seconds", "maxretry", "backend", "filter", "current_banned_ips"),
    "ban-events.csv": ("timestamp", "jail", "ip"),
}
TEXT_POLICY = "apostrophe-prefix-formula-text-v1"


def default_root() -> Path:
    """Resolve the user-visible default without creating it."""
    return (Path.home() / "offenders-exports").resolve()


def safe_text(value):
    """Escape formula-like text after leading Unicode whitespace or C0 controls.

    Numbers and absent values pass through unchanged for csv's native encoding.
    """
    if isinstance(value, str):
        # Mixed Unicode whitespace and ASCII control prefixes are also ignored.
        index = 0
        while index < len(value) and (value[index].isspace() or ord(value[index]) < 33):
            index += 1
        if value[index:].startswith(("=", "+", "-", "@")):
            return "'" + value
    return value


def report_rows(report: Report):
    """Project normalized values, retaining report order and every event."""
    yield "report.csv", [(1, report.period, report.generated_at.isoformat(),
                          report.window_start.isoformat() if report.window_start else None,
                          report.total_bans, len(report.top_offenders), len(report.jail_statuses), TEXT_POLICY)]
    yield "top-offenders.csv", (_offender_row(rank, item) for rank, item in enumerate(report.top_offenders, 1))
    yield "jail-status.csv", ((j.name, j.currently_failed, j.total_failed, j.currently_banned,
                               j.total_banned, j.bantime, j.findtime, j.maxretry, j.backend,
                               j.filter_name, " ".join(j.banned_ips)) for j in report.jail_statuses)
    yield "ban-events.csv", ((event.timestamp.isoformat(), event.jail, event.ip) for event in report.events)


def _offender_row(rank, item):
    """Missing structured enrichment is unavailable, never a display placeholder."""
    country = item.enrichment.country if item.enrichment else None
    asn = item.enrichment.asn if item.enrichment else None
    return (rank, item.count, item.ip, country.state if country else "unavailable",
            country.value if country else None, asn.state if asn else "unavailable",
            asn.value if asn else None, asn.organization if asn else None)


def _publish(staging: Path, destination: Path) -> None:
    """Linux atomic no-replace rename also protects against concurrent exporters.

    Fail closed if libc/kernel/filesystem lacks renameat2; ordinary rename can
    overwrite an existing empty directory and therefore is not a safe fallback.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, "renameat2", None)
    if rename is None:
        raise OSError(errno.ENOSYS, "Atomic no-replace rename is unavailable")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(staging), -100, os.fsencode(destination), 1):
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(destination))


def export_report(report: Report, destination=None) -> Path:
    """Stage private files, then publish one complete, collision-safe bundle.

    TemporaryDirectory removes staging on handled errors. No acquisition or shell
    execution occurs here. Existing destination permissions are left untouched.
    """
    if report.period not in PERIODS:
        raise ValueError("Unsupported report period")
    root = Path(destination).expanduser().resolve() if destination is not None else default_root()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    name = f"offenders-{report.period}-{report.generated_at:%Y_%m_%d_T%H%M%S}"
    with tempfile.TemporaryDirectory(prefix=".offenders-export-", dir=root) as temporary:
        staging = Path(temporary)
        for filename, rows in report_rows(report):
            descriptor = os.open(staging / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow(SCHEMAS[filename])
                writer.writerows(tuple(safe_text(value) for value in row) for row in rows)
        suffix = 1
        while True:
            target = root / (name if suffix == 1 else f"{name}-{suffix}")
            try:
                _publish(staging, target)
                return target
            except FileExistsError:
                suffix += 1
