"""Read-only DB-IP current-generation health, readers, and bounded enrichment.

Only app-managed atomic generations are read. Refresh checks local data;
nothing downloads or creates files.
"""
from __future__ import annotations

import atexit
import ipaddress
import os
from collections import OrderedDict
from dataclasses import dataclass, replace
from pathlib import Path
from threading import RLock
from typing import Literal

CACHE_SIZE = 2048  # Per database; includes healthy negative lookups.


def resolve_data_root() -> Path:
    """Resolve the shared root without creating it."""
    return Path(os.environ.get("XDG_DATA_HOME") or
                Path.home() / ".local/share") / "offenders/geoip"


def validate_metadata(reader, kind: str | None = None):
    """Share MMDB metadata checks; acquisition additionally requires role evidence."""
    metadata = reader.metadata()
    if metadata.ip_version not in (4, 6) or not metadata.database_type:
        raise ValueError("Invalid MMDB metadata")
    if kind and kind not in metadata.database_type.lower():
        raise ValueError(f"MMDB metadata does not identify a {kind} database")


def validate_database(path: Path, kind: str):
    """Validate a staged database with the same Python reader used for lookups."""
    import maxminddb
    with maxminddb.open_database(str(path)) as reader:
        validate_metadata(reader, kind)
        # Traverse records to detect broken data sections before activation.
        for _, record in reader:
            if not isinstance(record, dict):
                raise ValueError("Invalid MMDB record")


@dataclass(frozen=True)
class DatabaseHealth:
    """Snapshot of a stable path and the generation inspected behind it."""

    path: str
    resolved_path: str | None = None
    exists: bool = False
    readable: bool = False
    generation: tuple | None = None
    mtime_ns: int | None = None
    reader_available: bool = False
    metadata_valid: bool = False
    state: str = "missing"
    detail: str = ""


@dataclass(frozen=True)
class LookupResult:
    """Mapped fields, healthy absence, and subsystem failures are distinct."""

    state: Literal["mapped", "unmapped", "unavailable"]
    value: str | None = None
    organization: str | None = None
    detail: str = ""


@dataclass(frozen=True)
class Enrichment:
    """Independent Country and ASN outcomes for one normalized address."""

    country: LookupResult
    asn: LookupResult


def _inspect(path: Path, target: Path, available: bool) -> DatabaseHealth:
    """Inspect the pinned target, keeping the stable current path in diagnostics."""
    health = DatabaseHealth(str(path), reader_available=available)
    try:
        resolved = target.resolve()
        health = replace(health, resolved_path=str(resolved))
        stat = resolved.stat()
        health = replace(
            health, exists=True, readable=os.access(resolved, os.R_OK),
            mtime_ns=stat.st_mtime_ns,
            generation=(str(resolved), stat.st_dev, stat.st_ino, stat.st_size,
                        stat.st_mtime_ns, stat.st_ctime_ns),
        )
        if not health.readable:
            return replace(health, state="unreadable", detail="Path is not readable")
        return replace(health, state="unchecked")
    except FileNotFoundError:
        return replace(health, state="missing", detail="Database target is missing")
    except PermissionError as error:
        return replace(health, state="unreadable", detail=str(error)[:240])
    except (OSError, RuntimeError) as error:
        return replace(health, state="unreadable", detail=str(error)[:240])


class _Database:
    """Own one reader and its generation-specific LRU under the service lock."""

    def __init__(self, kind: str, path: Path, cache_size: int):
        self.kind = kind
        self.path = path
        self.cache_size = cache_size
        self.reader = None
        self.identity = None
        self.cache = OrderedDict()
        self.health = DatabaseHealth(str(path))
        self._corrupt = None
        self._invalid_error = ()

    def close(self):
        """Release the reader and every result associated with its generation."""
        reader, self.reader = self.reader, None
        self.identity = None
        self.cache.clear()
        if reader is not None:
            reader.close()

    def refresh(self, backend, backend_error: str, current: Path):
        """Reuse the current reader or replace it when the inspected file changes."""
        self._invalid_error = backend.InvalidDatabaseError if backend else ()
        health = _inspect(self.path, current / self.path.name, backend is not None)
        if health.state == "unchecked":
            health = self._validate(health, backend, backend_error)
        if health.state != "healthy":
            self.close()
        self.health = health

    def _validate(self, health, backend, backend_error):
        """Validate metadata once per reader; remember corruption for this file identity."""
        if self._corrupt and self._corrupt[0] == health.generation:
            return replace(health, state="invalid", detail=self._corrupt[1])
        if backend is None:
            return replace(health, state="reader_unavailable", detail=backend_error)
        if health.generation == self.identity and self.reader is not None:
            return replace(health, state="healthy", metadata_valid=True)
        reader = None
        try:
            reader = backend.open_database(health.resolved_path)
            validate_metadata(reader)
            self.close()
            self.reader, reader = reader, None
            self.identity = health.generation
            self._corrupt = None
            return replace(health, state="healthy", metadata_valid=True)
        except PermissionError as error:
            return replace(health, state="unreadable", detail=str(error)[:240])
        except (backend.InvalidDatabaseError, ValueError) as error:
            return replace(health, state="invalid", detail=str(error)[:240])
        except Exception as error:
            return replace(health, state="reader_unavailable", detail=str(error)[:240])
        finally:
            if reader is not None:
                reader.close()

    def lookup(self, ip: str) -> LookupResult:
        """Cache successful reads, including absent or incomplete records."""
        if self.reader is None:
            return LookupResult("unavailable", detail="Current database is unavailable")
        if ip in self.cache:
            self.cache.move_to_end(ip)
            return self.cache[ip]
        try:
            # An IPv4-only database cannot contain an IPv6 record.
            if ":" in ip and self.reader.metadata().ip_version == 4:
                result = LookupResult("unmapped")
            else:
                result = self._record(self.reader.get(ip))
        except self._invalid_error as error:
            detail = str(error)[:240]
            self._corrupt = (self.identity, detail)
            self.close()
            self.health = replace(self.health, state="invalid", detail=detail)
            return LookupResult("unavailable", detail=detail)
        except Exception as error:
            return LookupResult("unavailable", detail=str(error)[:240])
        self.cache[ip] = result
        if len(self.cache) > self.cache_size:
            self.cache.popitem(last=False)
        return result

    def _record(self, record) -> LookupResult:
        """Extract only the generic DB-IP fields used by the dashboard."""
        if not isinstance(record, dict):
            return LookupResult("unmapped")
        if self.kind == "country":
            country = record.get("country")
            names = country.get("names") if isinstance(country, dict) else None
            value = names.get("en") if isinstance(names, dict) else None
            if isinstance(value, str) and value:
                return LookupResult("mapped", value)
        else:
            number = record.get("autonomous_system_number")
            org = record.get("autonomous_system_organization")
            org = org if isinstance(org, str) and org else None
            if isinstance(number, int) and not isinstance(number, bool) and number > 0:
                return LookupResult("mapped", str(number), org)
            if org:
                return LookupResult("unmapped", organization=org,
                                    detail="ASN number is absent or invalid")
        return LookupResult("unmapped", detail="Expected record fields are absent or invalid")


class GeoIP:
    """Serialize refresh/read/close to prevent reader lifetime races."""

    def __init__(self, data_root: Path | None = None, cache_size: int = CACHE_SIZE):
        if cache_size < 1:
            raise ValueError("cache_size must be positive")
        if data_root is None:
            data_root = resolve_data_root()
        self.data_root = data_root
        self._lock = RLock()
        self._databases = {
            kind: _Database(kind, data_root / "current" / f"dbip-{kind}-lite.mmdb", cache_size)
            for kind in ("country", "asn")
        }

    def refresh(self) -> dict[str, DatabaseHealth]:
        """Pin the current pair once before report enrichment, without any writes."""
        try:
            import maxminddb
            backend, error = maxminddb, ""
        except Exception as exc:
            backend, error = None, str(exc)[:240]
        with self._lock:
            # Resolve current once so an activation cannot mix generation months.
            current = self.data_root / "current"
            try:
                current = current.resolve()
            except (OSError, RuntimeError):
                pass  # Each database retains the bounded path-resolution failure.
            for database in self._databases.values():
                database.refresh(backend, error, current)
            return self.health()

    def health(self) -> dict[str, DatabaseHealth]:
        """Snapshot health, including corruption discovered during enrichment."""
        with self._lock:
            return {kind: database.health for kind, database in self._databases.items()}

    def lookup(self, ip: str) -> Enrichment:
        """Normalize valid IPs; public/private policy belongs to report parsing."""
        normalized = str(ipaddress.ip_address(ip))
        with self._lock:
            return Enrichment(self._databases["country"].lookup(normalized),
                              self._databases["asn"].lookup(normalized))

    def close(self):
        """Release process-owned readers at teardown or explicit shutdown."""
        with self._lock:
            for database in self._databases.values():
                database.close()


geoip = GeoIP()
atexit.register(geoip.close)
