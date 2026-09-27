"""Explicit read-only host snapshots; never part of ordinary report refresh."""
from __future__ import annotations

from dataclasses import dataclass, replace
import ipaddress
import re

from offenders_fail2ban import CommandFailure, CommandResult, run_host_command

# Fixed identity evidence only: ports never identify a service family.
CATALOG = (
    ("ssh", ("sshd",), ("ssh.service", "sshd.service")),
    ("nginx", ("nginx",), ("nginx.service",)),
    ("apache", ("apache2", "httpd"), ("apache2.service", "httpd.service")),
    ("caddy", ("caddy",), ("caddy.service",)),
    ("dovecot", ("dovecot",), ("dovecot.service",)),
    ("vsftpd", ("vsftpd",), ("vsftpd.service",)),
    ("proftpd", ("proftpd",), ("proftpd.service",)),
    ("pure-ftpd", ("pure-ftpd",), ("pure-ftpd.service",)),
)
UNITS = tuple(unit for _, _, units in CATALOG for unit in units)
SYSTEMCTL_ARGS = ("systemctl", "show", "--no-pager",
                  "--property=Id,LoadState,ActiveState,SubState", *UNITS)
DETAIL_LIMIT = 300


@dataclass(frozen=True)
class SourceHealth:
    """Command outcome plus bounded diagnostics; success can still be partial."""

    status: str  # successful, partial, unavailable, or not_attempted
    failure: CommandFailure | None = None
    detail: str = ""
    diagnostics: tuple[str, ...] = ()


@dataclass(frozen=True, order=True)
class ProcessOwner:
    """One exact process name/PID reported by ss."""

    name: str
    pid: int


@dataclass(frozen=True)
class Listener:
    """Local bind evidence, not a claim about Internet reachability."""

    protocol: str
    raw_address: str
    address: str | None
    scope: str | None
    port: int | None
    exposure: str
    owners: tuple[ProcessOwner, ...] = ()


@dataclass(frozen=True, order=True)
class UnitState:
    """Exact fields of an observed catalog unit."""

    id: str
    load_state: str
    active_state: str
    sub_state: str


@dataclass(frozen=True)
class ServiceObservation:
    """Supported family evidence with conservative listener observation state."""

    family: str
    state: str
    listeners: tuple[Listener, ...]
    units: tuple[UnitState, ...]


@dataclass(frozen=True)
class HostInventory:
    """Frozen snapshot whose empty collections must be read with source health."""

    listeners: tuple[Listener, ...]
    services: tuple[ServiceObservation, ...]
    primary: SourceHealth
    ownership: SourceHealth
    systemd: SourceHealth


def _key(listener: Listener) -> tuple:
    """Match normalized local endpoints, including IPv6 scope, never peers."""
    return (listener.protocol, listener.address or listener.raw_address,
            listener.scope or "", -1 if listener.port is None else listener.port)


def _bind(value: str) -> tuple:
    """Split numeric local endpoints while retaining unknown address literals."""
    raw, separator, port_text = value.rpartition(":")
    if not separator or not raw:
        raise ValueError("missing local address/port")
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    if port_text == "*":
        port = None
    elif re.fullmatch(r"[0-9]{1,5}", port_text) and int(port_text) <= 65535:
        port = int(port_text)
    else:
        raise ValueError("invalid numeric port")
    host, _, scope = raw.partition("%")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return raw, None, scope or None, port, "non_loopback" if raw == "*" else "unknown"
    exposure = "loopback" if address.is_loopback else "non_loopback"
    return raw, address.compressed, scope or None, port, exposure


def parse_listeners(output: str) -> tuple[tuple[Listener, ...], tuple[str, ...]]:
    """Parse ss rows independently and merge exact endpoint/owner duplicates."""
    listeners = {}
    diagnostics = []
    for number, line in enumerate(output.splitlines(), 1):
        if not line.strip():
            continue
        fields = line.split(None, 6)
        try:
            if len(fields) < 6 or (fields[0], fields[1]) not in (
                ("tcp", "LISTEN"), ("udp", "UNCONN"),
            ):
                raise ValueError("unexpected listener row")
            owners = tuple(sorted(set(ProcessOwner(name, int(pid)) for name, pid in
                re.findall(r'\("([^"\n]+)",pid=([0-9]+),fd=[0-9]+\)',
                           fields[6] if len(fields) > 6 else ""))))
            listener = Listener(fields[0], *_bind(fields[4]), owners)
            key = _key(listener)
            previous = listeners.get(key)
            if previous:
                listener = replace(listener, raw_address=min(previous.raw_address, listener.raw_address),
                                   owners=tuple(sorted(set(previous.owners + owners))))
            listeners[key] = listener
        except ValueError as error:
            diagnostics.append(f"line {number}: {error}: {line}"[:DETAIL_LIMIT])
    return tuple(listeners[key] for key in sorted(listeners)), tuple(diagnostics)


def _health(result: CommandResult, diagnostics: tuple[str, ...] = ()) -> SourceHealth:
    """Keep failure categories without storing unbounded command streams."""
    status = "unavailable" if result.failure else "partial" if diagnostics else "successful"
    return SourceHealth(status, result.failure, (result.stderr or result.detail)[:DETAIL_LIMIT], diagnostics)


def _units(output: str) -> tuple[tuple[UnitState, ...], tuple[str, ...]]:
    """Read fixed show records; missing/malformed records remain limitations."""
    units = set()
    seen = set()
    diagnostics = []
    for block in re.split(r"\n\s*\n", output.strip()):
        fields = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        identity = fields.get("Id")
        if identity not in UNITS or not all(fields.get(k) for k in
                                           ("LoadState", "ActiveState", "SubState")):
            diagnostics.append(f"invalid systemd record: {block}"[:DETAIL_LIMIT])
            continue
        seen.add(identity)
        if fields["LoadState"] != "not-found":
            units.add(UnitState(identity, fields["LoadState"], fields["ActiveState"], fields["SubState"]))
    # Aliases may resolve to the same canonical Id, so missing Ids alone cannot
    # establish absence. The query is successful but its inventory is partial.
    if seen != set(UNITS):
        diagnostics.append("Some catalog unit identities were not returned (possibly aliases).")
    return tuple(sorted(units)), tuple(diagnostics)


def _services(listeners: tuple[Listener, ...], units: tuple[UnitState, ...],
              owners_complete: bool) -> tuple[ServiceObservation, ...]:
    """Derive family states only from exact process names and catalog units."""
    observations = []
    for family, names, unit_names in CATALOG:
        matching = tuple(row for row in listeners if any(owner.name in names for owner in row.owners))
        loaded = tuple(unit for unit in units if unit.id in unit_names)
        if not matching and not loaded:
            continue
        exposure = {row.exposure for row in matching}
        if "non_loopback" in exposure:
            state = "listening_non_loopback"
        elif "unknown" in exposure:
            state = "active_listener_unknown"
        elif matching:
            state = "listening_loopback"
        elif any(unit.active_state == "active" for unit in loaded):
            state = "active_no_matching_listener_observed" if owners_complete else "active_listener_unknown"
        else:
            state = "installed_inactive"
        observations.append(ServiceObservation(family, state, matching, loaded))
    return tuple(observations)


def discover_host_inventory() -> HostInventory:
    """Acquire one bounded snapshot explicitly, outside report/UI refresh paths.

    Non-loopback binds may be reachable beyond loopback depending on namespaces,
    routes and firewall policy. No reachability or coverage recommendation follows.
    """
    primary_result = run_host_command(["ss", "-H", "-lntu"], timeout=8, sudo=False)
    listeners, diagnostics = ((), ()) if primary_result.failure else parse_listeners(primary_result.stdout)
    primary = _health(primary_result, diagnostics)
    ownership = SourceHealth("not_attempted", detail="Primary listener scan unavailable.")
    if not primary_result.failure:
        result = run_host_command(["ss", "-H", "-lntup"], timeout=8, sudo=True)
        enriched, errors = ((), ()) if result.failure else parse_listeners(result.stdout)
        owner_map = {_key(row): row.owners for row in enriched}
        listeners = tuple(replace(row, owners=owner_map.get(_key(row), ())) for row in listeners)
        if not result.failure and any(not row.owners for row in listeners):
            errors += ("Process owners missing for one or more canonical endpoints.",)
        ownership = _health(result, errors)
    result = run_host_command(list(SYSTEMCTL_ARGS), timeout=8, sudo=False)
    units, errors = ((), ()) if result.failure else _units(result.stdout)
    systemd = _health(result, errors)
    complete = primary.status == ownership.status == "successful"
    return HostInventory(listeners, _services(listeners, units, complete), primary, ownership, systemd)
