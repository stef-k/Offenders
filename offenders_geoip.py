"""Read-only DB-IP source selection, reusable readers, and bounded enrichment.

Stable filenames in the XDG data directory take precedence independently over
legacy system files. Refresh checks local generations; nothing downloads data.
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

GEO_COUNTRY_DB = "/usr/share/GeoIP/dbip-country-lite.mmdb"
GEO_ASN_DB = "/usr/share/GeoIP/dbip-asn-lite.mmdb"
CACHE_SIZE = 2048  # Per database; includes healthy negative lookups.


@dataclass(frozen=True)
class CandidateHealth:
    """Snapshot of a stable path and the generation inspected behind it."""

    source: str
    path: str
    is_symlink: bool = False
    resolved_path: str | None = None
    exists: bool = False
    readable: bool = False
    generation: tuple | None = None
    mtime_ns: int | None = None
    reader_available: bool = False
    metadata_valid: bool = False
    state: str = "missing"
    detail: str = ""
    active: bool = False


@dataclass(frozen=True)
class DatabaseHealth:
    """Keep preferred-source failures visible even when fallback succeeds."""

    candidates: tuple[CandidateHealth, ...]
    source: str = "none"
    fallback: bool = False


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


def _inspect(path: Path, source: str, available: bool) -> CandidateHealth:
    """Inspect without modifying paths, including dangling stable symlinks."""
    health = CandidateHealth(source, str(path), reader_available=available)
    try:
        health = replace(health, is_symlink=path.is_symlink())
        resolved = path.resolve()
        health = replace(health, resolved_path=str(resolved))
        stat = path.stat()
        health = replace(
            health, exists=True, readable=os.access(path, os.R_OK),
            mtime_ns=stat.st_mtime_ns,
            generation=(str(resolved), stat.st_dev, stat.st_ino, stat.st_size,
                        stat.st_mtime_ns, stat.st_ctime_ns),
        )
        if not health.readable:
            return replace(health, state="unreadable", detail="Path is not readable")
        return replace(health, state="unchecked")
    except FileNotFoundError:
        state = "broken_symlink" if health.is_symlink else "missing"
        return replace(health, state=state, detail="Database target is missing")
    except PermissionError as error:
        return replace(health, state="unreadable", detail=str(error)[:240])
    except (OSError, RuntimeError) as error:
        return replace(health, state="unreadable", detail=str(error)[:240])


class _Database:
    """Own one reader and its generation-specific LRU under the service lock."""

    def __init__(self, kind: str, paths: tuple[Path, Path], cache_size: int):
        self.kind = kind
        self.paths = paths
        self.cache_size = cache_size
        self.reader = None
        self.identity = None
        self.cache = OrderedDict()
        self.health = DatabaseHealth(())
        self._validated = {}
        self._corrupt = {}
        self._invalid_error = ()

    def close(self):
        """Release the reader and every result associated with its generation."""
        reader, self.reader = self.reader, None
        self.identity = None
        self.cache.clear()
        if reader is not None:
            reader.close()

    def refresh(self, backend, backend_error: str):
        """Select the first healthy candidate, retaining both path diagnostics."""
        self._invalid_error = backend.InvalidDatabaseError if backend else ()
        candidates = []
        selected = None
        for source, path in zip(("app-managed", "legacy-system"), self.paths):
            health = _inspect(path, source, backend is not None)
            identity = (source, health.generation)
            if health.state == "unchecked":
                health = self._validate(health, identity, backend, backend_error,
                                        selected is None)
            if selected is None and health.state == "healthy":
                selected = source
                health = replace(health, active=True)
            candidates.append(health)
        if selected is None:
            self.close()
        self.health = DatabaseHealth(tuple(candidates), selected or "none",
                                     selected == "legacy-system")

    def _validate(self, health, identity, backend, backend_error, select):
        """Open candidates for metadata validation; reuse the active generation."""
        corrupt = self._corrupt.get(health.source)
        if corrupt and corrupt[0] == health.generation:
            return replace(health, state="invalid", detail=corrupt[1])
        if backend is None:
            return replace(health, state="reader_unavailable", detail=backend_error)
        if identity == self.identity and self.reader is not None:
            return replace(health, state="healthy", metadata_valid=True)
        previous = self._validated.get(health.source)
        if not select and previous and previous.generation == health.generation:
            return replace(previous, active=False)
        reader = None
        try:
            reader = backend.open_database(health.resolved_path)
            metadata = reader.metadata()
            if metadata.ip_version not in (4, 6) or not metadata.database_type:
                raise ValueError("Invalid MMDB metadata")
            if select:
                self.close()
                self.reader, reader = reader, None
                self.identity = identity
            health = replace(health, state="healthy", metadata_valid=True)
            self._validated[health.source] = health
            return health
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
            return LookupResult("unavailable", detail="No healthy database selected")
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
            source, generation = self.identity
            self._corrupt[source] = (generation, detail)
            candidates = tuple(
                replace(item, state="invalid", detail=detail, active=False)
                if item.active else item for item in self.health.candidates
            )
            self.close()
            self.health = DatabaseHealth(candidates)
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

    def __init__(self, data_root: Path | None = None,
                 legacy_root: Path = Path("/usr/share/GeoIP"),
                 cache_size: int = CACHE_SIZE):
        if cache_size < 1:
            raise ValueError("cache_size must be positive")
        if data_root is None:
            data_root = Path(os.environ.get("XDG_DATA_HOME") or
                             Path.home() / ".local/share") / "offenders/geoip"
        self._lock = RLock()
        self._databases = {
            kind: _Database(kind, (data_root / filename, legacy_root / filename), cache_size)
            for kind, filename in (("country", Path(GEO_COUNTRY_DB).name),
                                   ("asn", Path(GEO_ASN_DB).name))
        }

    def refresh(self) -> dict[str, DatabaseHealth]:
        """Check source generations once before report enrichment."""
        try:
            import maxminddb
            backend, error = maxminddb, ""
        except Exception as exc:
            backend, error = None, str(exc)[:240]
        with self._lock:
            for database in self._databases.values():
                database.refresh(backend, error)
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
