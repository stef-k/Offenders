"""Explicit factual coverage snapshots; no log reads, recommendations, or UI hooks."""
from __future__ import annotations

import configparser
from dataclasses import dataclass
import fnmatch
import os
from pathlib import Path
import re
import stat

from offenders_fail2ban import (
    Fail2BanCommandError, Fail2BanParseError, JailSources, get_jail_list,
    get_jail_sources, journal_units,
)
from offenders_host import Listener, ServiceObservation
from offenders_sources import FILE_CANDIDATES, LogSource, LogSourceInventory, SourceAssociation

# Fixed direct configuration scope and byte budgets, shared across jails/filters.
MAX_CONFIG_FILES = 256
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
RAW_LIMIT = 65536
STOCK_FAMILIES = {
    "sshd": "ssh",
    **dict.fromkeys(("nginx-http-auth", "nginx-limit-req", "nginx-botsearch",
                     "nginx-bad-request"), "nginx"),
    **dict.fromkeys(("apache-auth", "apache-badbots", "apache-noscript", "apache-overflows",
                     "apache-nohome", "apache-botsearch", "apache-fakegooglebot",
                     "apache-modsecurity", "apache-shellshock"), "apache"),
    "dovecot": "dovecot", "vsftpd": "vsftpd", "proftpd": "proftpd", "pure-ftpd": "pure-ftpd",
}


@dataclass(frozen=True)
class ConfigFragment:
    """Configured identity, confined resolved target, and read/parse limitations."""

    path: str
    resolved_path: str | None
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class FilterDefinition:
    """Only existence and direct Definition journal evidence, never regex bodies."""

    name: str
    readable: bool
    journalmatch: str
    journal_units: tuple[str, ...]
    fragments: tuple[ConfigFragment, ...]
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class JailDefinition:
    """Effective raw INI fields with provenance, without general interpolation."""

    name: str
    enabled: bool | None
    filter_raw: str
    filter_stem: str | None
    logpath: str
    patterns: tuple[str, ...]
    backend: str
    fragments: tuple[ConfigFragment, ...]
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class StaticInventory:
    """Deterministic fixed-root definitions and limitations that may hide evidence."""

    jails: tuple[JailDefinition, ...]
    filters: tuple[FilterDefinition, ...]
    fragments: tuple[ConfigFragment, ...]
    limitations: tuple[str, ...]
    jail_reads_complete: bool = True


@dataclass(frozen=True)
class DefinitionMatch:
    """A disabled candidate's concrete or explicitly family-only relevance."""

    name: str
    reason: str
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class CoverageTarget:
    """One source-family association, retaining source and observation evidence."""

    source: LogSource
    association: SourceAssociation | None
    classification: str
    running_jails: tuple[str, ...]
    disabled_definitions: tuple[DefinitionMatch, ...]
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class InsufficientFact:
    """Observed listener/service without a usable source-family target."""

    observation: Listener | ServiceObservation
    reason: str
    classification: str = "insufficient_evidence"


@dataclass(frozen=True)
class CoverageInventory:
    """Exact upstream snapshot plus runtime/static evidence and derived targets."""

    source_inventory: LogSourceInventory
    running_jails: tuple[JailSources, ...]
    runtime_error: Fail2BanCommandError | Fail2BanParseError | None
    static: StaticInventory
    targets: tuple[CoverageTarget, ...]
    unassociated_listeners: tuple[InsufficientFact, ...]
    services_without_sources: tuple[InsufficientFact, ...]


def _permission_limitation(path: Path) -> str:
    """Describe denied static configuration access without Python error formatting."""
    return (f"Static Fail2Ban configuration unavailable: the current user cannot read {path}. "
            "Coverage results may be incomplete.")[:300]


def _config_paths(root: Path) -> tuple[list[Path], tuple[str, ...]]:
    """Enumerate only direct fixed directories, stopping at the candidate bound."""
    paths = []
    limitations = []
    try:
        if not root.is_dir():
            return [], ("Fail2Ban configuration root unavailable",)
        for name in ("jail.conf", "jail.local"):
            path = root / name
            if path.exists() or path.is_symlink():
                paths.append(path)
        for name in ("jail.d", "filter.d"):
            directory = root / name
            if not directory.resolve().is_relative_to(root):
                limitations.append(f"{directory}: directory escapes configuration root")
                continue
            if not directory.exists():
                continue
            with os.scandir(directory) as entries:
                for entry in entries:
                    if not entry.name.endswith((".conf", ".local")):
                        continue
                    paths.append(Path(entry.path))
                    if len(paths) > MAX_CONFIG_FILES:
                        # Do not select an arbitrary filesystem-order subset.
                        return [], ("Configuration candidate count exceeds bound",)
    except PermissionError:
        limitations.append(_permission_limitation(root))
    except (OSError, RuntimeError) as error:
        limitations.append(f"Configuration enumeration unavailable: {error}"[:300])
    return sorted(paths), tuple(limitations)


class _ConfigReader:
    """Share a total byte budget and preserve every attempted fragment's outcome."""

    def __init__(self, root: Path):
        self.root = root
        self.bytes_read = 0
        self.fragments = []

    def read(self, path: Path) -> tuple[configparser.RawConfigParser | None, ConfigFragment]:
        """Read regular confined config only, bounding bytes before INI parsing."""
        resolved = None
        try:
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(self.root):
                raise ValueError("config symlink escapes configuration root")
            # Nonblocking/no-follow prevents a replaced leaf symlink or FIFO from
            # turning a metadata inspection into an arbitrary or blocking read.
            descriptor = os.open(resolved, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            with os.fdopen(descriptor, "rb") as stream:
                metadata = os.fstat(stream.fileno())
                if not stat.S_ISREG(metadata.st_mode):
                    raise ValueError("config is not a regular file")
                remaining = MAX_TOTAL_BYTES - self.bytes_read
                if metadata.st_size > min(MAX_FILE_BYTES, remaining):
                    raise ValueError("configuration file/total byte bound exceeded")
                content = stream.read(min(MAX_FILE_BYTES, remaining) + 1)
                self.bytes_read += len(content)
                if len(content) > min(MAX_FILE_BYTES, remaining):
                    raise ValueError("configuration file/total byte bound exceeded")
            parser = configparser.RawConfigParser(interpolation=None, strict=True)
            parser.read_string(content.decode("utf-8"), source=str(path))
            fragment = ConfigFragment(str(path), str(resolved))
        except PermissionError:
            fragment = ConfigFragment(str(path), str(resolved) if resolved else None,
                                      (_permission_limitation(path),))
            parser = None
        except (OSError, RuntimeError, ValueError, configparser.Error) as error:
            fragment = ConfigFragment(str(path), str(resolved) if resolved else None,
                                      (f"{path}: {error}"[:300],))
            parser = None
        self.fragments.append(fragment)
        return parser, fragment


def _merge(paths: list[Path], reader: _ConfigReader) -> tuple[dict, dict, dict, tuple[str, ...]]:
    """Merge raw defaults/explicit options separately, retaining contributing files."""
    defaults, sections, origins = {}, {}, {}
    limitations = []
    for path in paths:
        parser, fragment = reader.read(path)
        if parser is None:
            limitations.extend(fragment.limitations)
            continue
        if parser.has_section("INCLUDES"):
            limitations.append(f"{path}: include chains are not resolved")
        if parser.defaults():
            defaults.update(parser.defaults())
            origins.setdefault("DEFAULT", []).append(fragment)
        for name in parser.sections():
            if name == "INCLUDES":
                continue
            # RawConfigParser.items includes defaults; merging those as explicit
            # values would incorrectly overwrite earlier section overrides.
            sections.setdefault(name, {}).update(parser._sections[name])
            origins.setdefault(name, []).append(fragment)
    return defaults, sections, origins, tuple(limitations)


def _raw(value: str, limitations: list[str]) -> str:
    """Do not correlate truncated raw fields as if they were complete values."""
    if len(value) > RAW_LIMIT:
        limitations.append("Raw configuration field exceeds evidence bound")
    return value[:RAW_LIMIT]


def _filter_stem(value: str, name: str) -> str | None:
    """Resolve only the documented jail-name default and simple parameter suffix."""
    value = value.replace("%(__name__)s", name)
    match = re.fullmatch(r"([A-Za-z0-9_.-]+)(?:\[.*\])?", value, re.DOTALL)
    return match[1] if match and match[1] not in (".", "..") else None


def _patterns(value: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Accept literal absolute lines/globs only; never expand or scan sources."""
    patterns, limitations = [], []
    for line in value.splitlines():
        line = line.strip()
        if not line:
            continue
        if not line.startswith("/") or re.search(r"[%<>$`{}\\\s]", line):
            limitations.append("Unresolved or unsupported static logpath syntax")
        else:
            patterns.append(os.path.normpath(line))
    return tuple(sorted(set(patterns))), tuple(sorted(set(limitations)))


def _jail(name: str, fields: dict, fragments: tuple[ConfigFragment, ...]) -> JailDefinition:
    """Project one effective section without treating unknown values as disabled."""
    limitations = []
    enabled = {"true": True, "yes": True, "1": True, "on": True,
               "false": False, "no": False, "0": False, "off": False}.get(
                   fields.get("enabled", "").strip().lower())
    raw_filter = _raw(fields.get("filter", ""), limitations)
    logpath = _raw(fields.get("logpath", ""), limitations)
    backend = _raw(fields.get("backend", ""), limitations)
    stem = _filter_stem(raw_filter, name) if len(fields.get("filter", "")) <= RAW_LIMIT else None
    patterns, errors = _patterns(logpath)
    if len(fields.get("logpath", "")) > RAW_LIMIT:
        patterns = ()
    if enabled is None:
        limitations.append("Static enabled state is unknown")
    if stem is None:
        limitations.append("Filter identity is unresolved")
    return JailDefinition(name, enabled, raw_filter, stem, logpath, patterns, backend,
                          fragments, tuple(sorted(set(limitations) | set(errors))))


def _filter(name: str, paths: list[Path], reader: _ConfigReader) -> FilterDefinition:
    """Merge conf then local; retain direct journal evidence despite include gaps."""
    start = len(reader.fragments)
    defaults, sections, _, errors = _merge(paths, reader)
    limitations = list(errors)
    fields = {**defaults, **sections.get("Definition", {})}
    value = fields.get("journalmatch", "")
    raw = _raw(value, limitations)
    units = journal_units(value) if len(value) <= RAW_LIMIT else ()
    if value and (not units or re.search(r"[%<>$`]", value)):
        limitations.append("Filter journal source relationship is not fully resolved")
    fragments = tuple(reader.fragments[start:])
    return FilterDefinition(name, any(not row.limitations for row in fragments),
                            raw, () if errors else units, fragments, tuple(limitations))


def discover_static(root: Path = Path("/etc/fail2ban")) -> StaticInventory:
    """Inventory bounded direct config in Fail2Ban precedence order as current user."""
    root = Path(root).absolute()
    try:
        root = root.resolve(strict=True)
    except PermissionError:
        return StaticInventory((), (), (), (_permission_limitation(root),), False)
    except (OSError, RuntimeError) as error:
        return StaticInventory((), (), (), (f"Configuration root unavailable: {error}"[:300],), False)
    paths, errors = _config_paths(root)
    reader = _ConfigReader(root)
    jail_paths = [path for path in paths if path.parent != root / "filter.d"]
    def precedence(path: Path) -> tuple[int, str]:
        """Order the four fixed jail layers, lexically within fragment layers."""
        layer = (0 if path.name == "jail.conf" and path.parent == root else
                 2 if path.name == "jail.local" and path.parent == root else
                 1 if path.suffix == ".conf" else 3)
        return layer, path.name
    defaults, sections, origins, jail_errors = _merge(sorted(jail_paths, key=precedence), reader)
    # Unresolved includes can override enabled/filter/source fields, including
    # explicit section fields that outrank later defaults in a before include.
    # Without resolving those fields' provenance, no disabled fact is proven.
    jail_reads_complete = not errors and not jail_errors
    jails = tuple(_jail(name, {**defaults, **fields},
                        tuple(dict.fromkeys(origins.get("DEFAULT", []) + origins[name])))
                  for name, fields in sorted(sections.items()))
    filter_names = sorted({path.stem for path in paths if path.parent == root / "filter.d"})
    filters = tuple(_filter(name, sorted((path for path in paths
                                         if path.parent == root / "filter.d" and path.stem == name),
                                        key=lambda path: path.suffix), reader)
                    for name in filter_names)
    read_errors = tuple(error for fragment in reader.fragments for error in fragment.limitations)
    return StaticInventory(jails, filters, tuple(reader.fragments),
                           tuple(sorted(set(errors + jail_errors + read_errors))), jail_reads_complete)


def _file_match(source: LogSource, paths: tuple[str, ...], *, patterns: bool = False) -> bool:
    """Compare known strings only, including the upstream resolved target identity."""
    identities = tuple(os.path.normpath(path) for path in (source.identity, source.resolved_path) if path)
    if patterns:
        # A path glob's '*' cannot cross a directory separator.
        return any(len(identity.split("/")) == len(pattern.split("/")) and
                   all(fnmatch.fnmatchcase(part, rule) for part, rule in
                       zip(identity.split("/"), pattern.split("/")))
                   for identity in identities for pattern in paths)
    return any(identity == os.path.normpath(path) for identity in identities for path in paths)


def _runtime_match(source: LogSource, jail: JailSources) -> bool:
    """Names never imply runtime source coverage."""
    if source.kind == "file":
        return _file_match(source, jail.logpaths or ())
    return source.kind == "journal" and source.identity in jail.journal_units


def _relevance(source: LogSource, family: str | None, jail: JailDefinition,
               definition: FilterDefinition | None) -> str | None:
    """Prefer concrete source evidence over the exact family catalog."""
    if source.kind == "file" and _file_match(source, jail.patterns, patterns=True):
        return "literal configured file pattern"
    if source.kind == "journal" and definition and source.identity in definition.journal_units:
        return "exact filter journal unit"
    if family is not None and STOCK_FAMILIES.get(jail.name) == family:
        return "exact stock family catalog"
    return None


def _target(source: LogSource, association: SourceAssociation | None,
            running: tuple[JailSources, ...], runtime_error: Exception | None,
            static: StaticInventory) -> CoverageTarget:
    """Apply factual precedence, allowing negatives only with complete evidence."""
    family = association.family if association else None
    limitations = list(static.limitations)
    if family not in FILE_CANDIDATES or source.kind not in ("file", "journal"):
        limitations.append("No supported source-family identity")
    if runtime_error:
        limitations.append(f"Runtime jail inventory unavailable: {runtime_error}"[:300])
    matches = tuple(jail.name for jail in running if _runtime_match(source, jail))
    query = "logpath" if source.kind == "file" else "journalmatch"
    for jail in running:
        if query in jail.errors:
            limitations.append(f"{jail.name}: {query} unavailable: {jail.errors[query]}"[:300])
        if (source.kind == "journal" and jail.journalmatch
                and (not jail.journal_units or re.search(r"[%<>$`]", jail.journalmatch))):
            limitations.append(f"{jail.name}: runtime journal source relationship is not fully resolved")
    filters = {row.name: row for row in static.filters}
    running_names = {row.name for row in running}
    candidates = []
    for jail in static.jails:
        if jail.name in running_names:
            continue
        definition = filters.get(jail.filter_stem)
        relevance = _relevance(source, family, jail, definition)
        limitations.extend(f"{jail.name}: {error}" for error in jail.limitations)
        if definition is None or not definition.readable:
            limitations.append(f"{jail.name}: filter definition unavailable")
        if definition:
            limitations.extend(f"{jail.name}: {error}" for error in definition.limitations)
        if jail.enabled is True:
            limitations.append(f"{jail.name}: configured-enabled-not-running")
        if (relevance and jail.enabled is False and definition and definition.readable
                and static.jail_reads_complete):
            reason_limits = (("Family relevance only; exact source relationship not proven",)
                             if relevance == "exact stock family catalog" else ())
            candidates.append(DefinitionMatch(jail.name, relevance, reason_limits))
    classification = ("covered_enabled" if matches else "available_disabled" if candidates else
                      "insufficient_evidence" if limitations else "no_obvious_match")
    return CoverageTarget(source, association, classification, matches, tuple(candidates),
                          tuple(sorted(set(limitations))))


def discover_coverage(source_inventory: LogSourceInventory, *,
                      config_root: Path = Path("/etc/fail2ban")) -> CoverageInventory:
    """Consume one supplied snapshot explicitly; never reacquire host/source state."""
    runtime_error = None
    running = ()
    try:
        running = tuple(get_jail_sources(name) for name in sorted(get_jail_list()))
    except (Fail2BanCommandError, Fail2BanParseError) as error:
        runtime_error = error
    static = discover_static(config_root)
    targets = tuple(_target(source, association, running, runtime_error, static)
                    for source in sorted(source_inventory.sources, key=lambda row: (row.kind, row.identity))
                    for association in sorted(set(source.associations)) or (None,))
    families = {association.family for source in source_inventory.sources for association in source.associations}
    missing = tuple(InsufficientFact(service, "Observed service has no discovered source")
                    for service in sorted(source_inventory.host_inventory.services,
                                          key=lambda row: (row.family, row.state)) if service.family not in families)
    listeners = tuple(InsufficientFact(listener, "Listener has no supported family association")
                      for listener in source_inventory.unassociated_listeners)
    return CoverageInventory(source_inventory, running, runtime_error, static, targets, listeners, missing)
