"""Metadata-only local source discovery from one explicit host snapshot."""
from __future__ import annotations

from dataclasses import dataclass, replace
import os
from pathlib import Path
import stat

from offenders_fail2ban import CommandFailure, run_host_command
from offenders_host import HostInventory, Listener

# Deliberately fixed Ubuntu/Debian candidates, never expanded through scanning.
FILE_CANDIDATES = {
    "ssh": ("/var/log/auth.log",),
    "nginx": ("/var/log/nginx/access.log", "/var/log/nginx/error.log"),
    "apache": ("/var/log/apache2/access.log", "/var/log/apache2/error.log",
               "/var/log/httpd/access_log", "/var/log/httpd/error_log"),
    "caddy": (),
    "dovecot": ("/var/log/mail.log", "/var/log/dovecot.log"),
    "vsftpd": ("/var/log/vsftpd.log", "/var/log/auth.log"),
    "proftpd": ("/var/log/proftpd/proftpd.log", "/var/log/auth.log"),
    "pure-ftpd": ("/var/log/auth.log",),
}
DETAIL_LIMIT = 300


@dataclass(frozen=True, order=True)
class SourceAssociation:
    """Tie each candidate to its observed family and retained host state."""

    family: str
    service_state: str
    reason: str


@dataclass(frozen=True)
class LogSource:
    """One checked candidate; readable journals imply queryability, not entries.

    File identities retain configured paths, including symlinks. Optional file
    facts remain unknown when metadata is unavailable. No content is retained.
    """

    kind: str
    identity: str
    state: str  # readable, unreadable, missing, unsupported, unavailable
    associations: tuple[SourceAssociation, ...] = ()
    resolved_path: str | None = None
    is_regular: bool | None = None
    directly_readable: bool | None = None
    failure: CommandFailure | None = None
    detail: str = ""

    @property
    def families(self) -> tuple[str, ...]:
        """Return the sorted union without duplicating association authority."""
        return tuple(sorted({row.family for row in self.associations}))


@dataclass(frozen=True)
class LogSourceInventory:
    """Explicit source snapshot retaining the exact input and its limitations."""

    host_inventory: HostInventory
    sources: tuple[LogSource, ...]
    unassociated_listeners: tuple[Listener, ...]


def probe_file(path: str) -> LogSource:
    """Follow metadata symlinks and check effective-user access, never open logs."""
    try:
        metadata = os.stat(path)
        resolved = str(Path(path).resolve(strict=True))
        regular = stat.S_ISREG(metadata.st_mode)
        if not regular:
            return LogSource("file", path, "unsupported", resolved_path=resolved,
                             is_regular=False)
        # Linux supports effective_ids; on other platforms use their access API.
        options = {"effective_ids": True} if os.access in os.supports_effective_ids else {}
        readable = os.access(path, os.R_OK, **options)
        return LogSource("file", path, "readable" if readable else "unreadable",
                         resolved_path=resolved, is_regular=True,
                         directly_readable=readable)
    except FileNotFoundError as error:
        return LogSource("file", path, "missing", detail=str(error)[:DETAIL_LIMIT])
    except (OSError, RuntimeError) as error:
        return LogSource("file", path, "unavailable", detail=str(error)[:DETAIL_LIMIT])


def probe_journal(unit: str) -> LogSource:
    """Check queryability once with no historical entries requested or retained."""
    result = run_host_command(
        ["journalctl", "--quiet", "--no-pager", "--unit", unit, "--lines=0"],
        timeout=8, sudo=False,
    )
    return LogSource("journal", unit, "unavailable" if result.failure else "readable",
                     failure=result.failure,
                     detail=(result.stderr or result.detail)[:DETAIL_LIMIT])


def discover_log_sources(host_inventory: HostInventory) -> LogSourceInventory:
    """Check only supplied supported observations, once per physical identity."""
    candidates: dict[tuple[str, str], set[SourceAssociation]] = {}
    associated_listeners = set()
    for service in host_inventory.services:
        if service.family not in FILE_CANDIDATES:
            continue
        associated_listeners.update(service.listeners)
        for path in FILE_CANDIDATES[service.family]:
            association = SourceAssociation(service.family, service.state,
                                            f"fixed standard file candidate: {path}")
            candidates.setdefault(("file", path), set()).add(association)
        for unit in service.units:
            if unit.load_state != "loaded":
                continue
            association = SourceAssociation(service.family, service.state,
                                            f"observed loaded systemd unit: {unit.id}")
            candidates.setdefault(("journal", unit.id), set()).add(association)
    sources = []
    for (kind, identity), associations in sorted(candidates.items()):
        source = probe_file(identity) if kind == "file" else probe_journal(identity)
        sources.append(replace(source, associations=tuple(sorted(associations))))
    unassociated = tuple(row for row in host_inventory.listeners if row not in associated_listeners)
    return LogSourceInventory(host_inventory, tuple(sources), unassociated)
