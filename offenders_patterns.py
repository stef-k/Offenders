"""Pure, source-gated recognition of bounded #30 evidence; #33 owns findings."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import re
from urllib.parse import unquote

from offenders_evidence import EvidenceRecord, EvidenceSnapshot, RecordKey, SourceKey, SourceResult

# This is a format catalog, not a scanner heuristic or a Fail2Ban filter interpreter.
SUPPORTED = frozenset(("ssh", "nginx", "apache", "dovecot", "vsftpd", "proftpd", "pure-ftpd"))
MAX_EXAMPLES = 3
EXAMPLE_BYTES = 512
MAX_LIMITATIONS = 32
LIMITATION_BYTES = 300
COUNT_NOTE = "event counts measure recognized log records, not unique sessions"
LOCAL_NOTE = "file timestamp lacks UTC offset; exact requested lookback cannot be enforced"
UNKNOWN_NOTE = "event timestamp missing or unsupported; no event time fabricated"
IP_NOTE = "source IP evidence incomplete"
MONTHS = {name: str(index).zfill(2) for index, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
# Capture timestamp prefixes separately so malformed dates can still yield events.
SYSLOG = re.compile(r"^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})\s+")
ISO = re.compile(r"^(?P<stamp>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:\d\d)?)\s+")
NGINX_TIME = re.compile(r"^(?P<stamp>\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)\s+")
APACHE_TIME = re.compile(r"^\[[A-Za-z]{3} (?P<stamp>[A-Za-z]{3}\s+\d{1,2} \d\d:\d\d:\d\d(?:\.\d+)? \d{4})\]\s+")
VSFTPD_TIME = re.compile(r"^[A-Za-z]{3} (?P<stamp>[A-Za-z]{3}\s+\d{1,2} \d\d:\d\d:\d\d \d{4})\s+")
ACCESS = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<stamp>[^\]]*)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) HTTP/\d(?:\.\d)?" '
    r'(?P<status>\d{3}) (?:\d+|-)(?:\s|$)')
# Program tags are only stripped after association gating, never used to infer a family.
TAGS = {"ssh": r"sshd(?:-session)?", "dovecot": r"dovecot(?:-auth)?",
        "vsftpd": r"vsftpd(?:\(pam_unix\))?", "proftpd": r"proftpd", "pure-ftpd": r"pure-ftpd"}


@dataclass(frozen=True)
class RecognizedEvent:
    """One recognized record in a family/source/time domain; text stays upstream."""

    family: str
    source_kind: str
    source_identity: str
    pattern_kind: str
    signature: str
    record_id: RecordKey
    source_ip: str | None
    timestamp: datetime | None
    timestamp_basis: str
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class PatternGroup:
    """Measured log-record recurrence, without recommendation or coverage policy."""

    family: str
    source_kind: str
    source_identity: str
    pattern_kind: str
    signature: str
    timestamp_basis: str
    event_count: int
    distinct_source_ip_count: int
    global_source_ip_count: int
    non_global_source_ip_count: int
    first_seen: datetime | None
    last_seen: datetime | None
    record_ids: tuple[RecordKey, ...]
    examples: tuple[str, ...]
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class SourceFamilyAnalysis:
    """Canonical source health with alias keys and an explicit UTC-window count."""

    source_kind: str
    source_identity: str
    family: str
    source_keys: tuple[SourceKey, ...]
    state: str
    input_record_count: int
    recognized_event_count: int
    ignored_record_count: int
    excluded_record_count: int
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class PatternInventory:
    """Retain the exact input snapshot for later factual coverage correlation."""

    evidence_snapshot: EvidenceSnapshot
    events: tuple[RecognizedEvent, ...]
    groups: tuple[PatternGroup, ...]
    analyses: tuple[SourceFamilyAnalysis, ...]


def _clip(text: str, size: int) -> str:
    """Bound encoded text without splitting Unicode characters."""
    return text.encode("utf-8", errors="replace")[:size].decode("utf-8", errors="ignore")


def _limitations(messages) -> tuple[str, ...]:
    """Keep bounded unique details and reserve a visible overflow marker."""
    result = []
    capped = False
    for message in messages:
        clipped = _clip(message, LIMITATION_BYTES)
        capped |= clipped != message
        if clipped not in result:
            if len(result) < MAX_LIMITATIONS:
                result.append(clipped)
            else:
                capped = True
    if capped:
        result = result[:MAX_LIMITATIONS - 1] + ["limitations capped (count or UTF-8 byte limit)"]
    return tuple(result)


def _ip(value: str | None, *, endpoint: bool = False) -> str | None:
    """Normalize only the recognizer's source field; never search arbitrary text."""
    if value is None:
        return None
    if endpoint and value.startswith("["):
        value = value[1:].split("]", 1)[0]
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        # Unbracketed IPv6 is an address, not an inferred address/port pair.
        if not endpoint or value.count(":") != 1:
            return None
        host, port = value.rsplit(":", 1)
        if not port.isdecimal():
            return None
        return _ip(host)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


def _prefix(text: str, family: str):
    """Return a supported leading time field and format, with no timezone guess."""
    formats = [(ISO, "iso"), (SYSLOG, "syslog")]
    if family == "nginx":
        formats.append((NGINX_TIME, "%Y/%m/%d %H:%M:%S"))
    if family == "apache":
        formats.append((APACHE_TIME, "%b %d %H:%M:%S %Y"))
    if family == "vsftpd":
        formats.append((VSFTPD_TIME, "%b %d %H:%M:%S %Y"))
    for regex, form in formats:
        match = regex.match(text)
        if match:
            return match, form
    return None, ""


def _date(stamp: str, form: str) -> datetime:
    """Parse English log months independently of the process locale."""
    for month, number in MONTHS.items():
        stamp = stamp.replace(month, number)
    form = form.replace("%b", "%m")
    if re.search(r":\d\d\.\d+", stamp):
        form = form.replace("%S", "%S.%f")
    return datetime.strptime(stamp, form)


def _timestamp(record: EvidenceRecord, family: str, kind: str, anchor: datetime):
    """Keep UTC, naive wall-clock, and missing evidence in separate domains."""
    if kind == "journal":
        value = record.timestamp
        if value is not None and value.utcoffset() is not None:
            return value.astimezone(timezone.utc), "utc", ()
        return None, "unknown", (UNKNOWN_NOTE,)
    access = ACCESS.match(record.text) if family in ("nginx", "apache") else None
    match, form = _prefix(record.text, family)
    try:
        if access:
            value = _date(access["stamp"], "%d/%b/%Y:%H:%M:%S %z")
        elif match and form == "iso":
            value = datetime.fromisoformat(match["stamp"].replace(",", "."))
        elif match and form == "syslog":
            stamp = match["stamp"]
            # Only infer current/previous calendar year. A same-day wall clock
            # ahead of UTC is not sufficient evidence of a year rollover.
            month_day = _date(stamp + " 2000", "%b %d %H:%M:%S %Y")
            year = anchor.year - ((month_day.month, month_day.day) > (anchor.month, anchor.day))
            value = month_day.replace(year=year)
        elif match:
            value = _date(match["stamp"], form)
        else:
            return None, "unknown", (UNKNOWN_NOTE,)
    except ValueError:
        return None, "unknown", (UNKNOWN_NOTE,)
    if value.utcoffset() is not None:
        return value.astimezone(timezone.utc), "utc", ()
    return value, "local_wall", (LOCAL_NOTE,)


def _body(text: str, family: str) -> str:
    """Remove only supported timestamp and family program envelopes."""
    match, _ = _prefix(text, family)
    body = text[match.end():] if match else text
    tag = TAGS.get(family)
    if tag:
        body = re.sub(r"^(?:\S+\s+)?" + tag + r"(?:\[\d+\])?:?\s+", "", body, count=1)
    return body


def _auth(family: str, body: str):
    """Recognize a small explicit authentication catalog and its tied IP field."""
    if family == "ssh":
        forms = ((r"Failed password for .+ from (?P<ip>\S+)", "ssh_failed_password"),
                 (r"Invalid user .* from (?P<ip>\S+)", "ssh_invalid_user"),
                 (r"(?:error: )?authentication (?:failure|error|failed)\b.* from (?P<ip>\S+)", "ssh_authentication_failure"))
        for regex, kind in forms:
            match = re.match(regex, body, re.I)
            if match:
                return kind, _ip(match["ip"])
    elif family == "dovecot":
        match = re.match(r"(?:imap|pop3|submission)-login: .*\(auth failed\b.*(?:^|[ ,])rip=(?P<ip>[^,\s]+)", body)
        if not match:
            match = re.match(
                r"(?:auth(?:-worker)?(?:\([^)]*\))?:\s+)?(?:Info: )?"
                r"(?:pam|passwd-file|sql|ldap)\([^,]*,(?P<ip>[^,)]+)(?:,[^)]*)?\): "
                r"(?:pam_authenticate\(\) failed|unknown user|Password mismatch)", body, re.I)
        if not match:
            match = re.match(r"pam_unix\(dovecot:auth\): authentication failure;.*\srhost=(?P<ip>\S+)", body)
        if match:
            return "dovecot_authentication_failure", _ip(match["ip"])
    elif family == "vsftpd":
        match = re.match(r'(?:\[pid \d+\] )?\[[^\]]*\] FAIL LOGIN: Client "(?P<ip>[^"]+)"', body)
        if not match:
            match = re.match(
                r"(?:\(pam_unix\)|pam_unix\(vsftpd:auth\):) "
                r"authentication failure;.*\srhost=(?P<ip>\S+)", body)
        if match:
            return "vsftpd_login_failure", _ip(match["ip"])
    elif family == "proftpd":
        match = re.match(r"\S+ \([^\[]*\[(?P<ip>[^\]]+)\]\)(?::| -) (?P<message>.*)", body)
        if match and _ip(match["ip"]):
            message = match["message"]
            if re.match(r"SECURITY VIOLATION: .*root login attempted", message, re.I):
                return "proftpd_root_login", _ip(match["ip"])
            if re.match(r"(?:USER .*\(Login failed\)|USER .*: no such user found from "
                        r"|Maximum login attempts \(\d+\) exceeded)", message):
                return "proftpd_login_failure", _ip(match["ip"])
    elif family == "pure-ftpd":
        match = re.match(r"\(\?@(?P<ip>[^)]+)\) (?:\[WARNING\] )?Authentication failed for user \[", body)
        if match:
            return "pure-ftpd_authentication_failure", _ip(match["ip"])
    return None


def _probe(path: str) -> str | None:
    """Classify explicit path categories, excluding queries and generic 4xx noise."""
    path = path.split("?", 1)[0].split("#", 1)[0]
    if not path.startswith("/"):
        return None
    # Two decoding passes cover common double-encoded traversal, with fixed work.
    path = unquote(unquote(path)).lower().replace("\\", "/")
    if re.search(r"(?:^|/)\.\.(?:/|$)", path):
        return "path_traversal"
    if re.search(r"/(?:phpmyadmin(?:[-\d.]+)?|pma|mysqladmin)(?:/|$)", path):
        return "database_admin"
    if re.search(r"/cgi-bin/(?:[^/]+/)*[^/]+$", path):
        return "cgi_script"
    if re.search(r"/(?:wp-login\.php|xmlrpc\.php)$", path):
        return "wordpress_auth"
    if re.search(r"/(?:\.env(?:\.[^/]*)?|\.(?:git|svn|hg))(?:/|$)", path):
        return "sensitive_dotfile"
    return None


def _web(family: str, body: str):
    """Parse HTTP request/error envelopes before interpreting their message fields."""
    access = ACCESS.match(body)
    if access:
        category = _probe(access["path"]) if 400 <= int(access["status"]) < 500 else None
        return ("path_probe", _ip(access["ip"]), category) if category else None
    if family == "nginx":
        match = re.match(r"\[error\] \d+#\d+: \*\d+ (?P<message>.*), "
                         r"client: (?P<ip>[^,\s]+), server: [^,]*(?P<rest>.*)$", body)
        if not match:
            return None
        message = match["message"]
        if re.fullmatch(r'user ".*"(?: was not found in ".*"|: password mismatch)', message):
            return "nginx_http_authentication_failure", _ip(match["ip"]), None
        request = re.match(r', request: "[A-Z]+ (?P<path>\S+) HTTP/\d(?:\.\d)?"', match["rest"])
        missing = re.fullmatch(r'(?:open\(\) ".*" failed|".*" is not found) \(2: No such file or directory\)', message)
        category = _probe(request["path"]) if request and missing else None
        return ("path_probe", _ip(match["ip"]), category) if category else None
    match = re.match(r"(?:\[(?!client )[^\]]+\]\s+)*"
                     r"\[client (?P<ip>\[[^\]]+\](?::\d+)?|[^\]]+)\]\s+"
                     r"(?:AH\d+: )?(?P<message>.*)", body)
    if match and re.match(
        r"(?:Digest: )?(?:user .*?(?: not found|: (?:authentication failure|password mismatch|authorization failure))"
        r"|(?:client used )?wrong authentication scheme|client denied by server configuration"
        r"|authorization failure|Authorization of user .* to access .* failed, reason:)(?=\W|$)",
        match["message"], re.I,
    ):
        return "apache_http_authentication_failure", _ip(match["ip"], endpoint=True), None
    return None


def _recognize(record: EvidenceRecord, family: str):
    """Dispatch only after source associations have authorized this family."""
    body = _body(record.text, family)
    if family in ("nginx", "apache"):
        return _web(family, body)
    result = _auth(family, body)
    return (*result, None) if result else None


def _source_notes(rows: list[SourceResult], snapshot: EvidenceSnapshot) -> tuple[str, ...]:
    """Propagate alias collection health and global completeness limitations."""
    notes = []
    if snapshot.truncated:
        notes.append("snapshot evidence truncated")
    for row in rows:
        if row.state != "collected":
            notes.append(f"source {row.source.identity}: {row.state}")
        if row.truncated:
            notes.append(f"source {row.source.identity}: truncated")
        notes.extend(row.limitations)
    notes.extend(snapshot.limitations)
    return _limitations(notes)


def _record_order(identity: RecordKey):
    """Total backend identity order, including mixed string/integer components."""
    return tuple((0, part) if isinstance(part, int) else (1, part) for part in identity)


def _analyze_pair(key, rows, records, snapshot):
    """Analyze one canonical source/family once, unioning only its alias records."""
    kind, identity, family = key
    ids = sorted({rid for row in rows for rid in row.record_ids}, key=_record_order)
    notes = list(_source_notes(rows, snapshot))
    available = any(row.state not in ("unavailable", "skipped") for row in rows)
    supported = family in SUPPORTED and kind in ("file", "journal")
    events = []
    ignored = excluded = 0
    for rid in ids:
        record = records[rid]
        recognized = _recognize(record, family) if available and supported else None
        if not recognized:
            ignored += 1
            continue
        pattern_kind, ip, category = recognized
        stamp, basis, event_notes = _timestamp(record, family, kind, snapshot.collected_at)
        if basis == "utc" and not snapshot.requested_since <= stamp <= snapshot.collected_at:
            excluded += 1
            continue
        event_notes = list(event_notes)
        if ip is None:
            event_notes.append(IP_NOTE)
        if record.text_truncated:
            event_notes.append("record text truncated")
        notes.extend(event_notes)
        signature = f"{family}:{pattern_kind}" + (f":{category}" if category else "")
        events.append(RecognizedEvent(family, kind, identity, pattern_kind, signature,
                                     rid, ip, stamp, basis, _limitations(event_notes)))
    if family == "pure-ftpd" and ignored:
        notes.append("Pure-FTPd catalog supports only English authentication-failed messages")
    if not available:
        state = "unavailable" if any(row.state == "unavailable" for row in rows) else "skipped"
    elif not supported:
        state = "unsupported"
        notes.append("no recognizer for this source family/kind")
    else:
        state = "partial" if notes else "analyzed"
    analysis = SourceFamilyAnalysis(kind, identity, family,
        tuple(sorted({(row.source.kind, row.source.identity) for row in rows})),
        state, len(ids), len(events), ignored, excluded, _limitations(notes))
    return events, analysis


def _group(events, records, source_notes) -> PatternGroup:
    """Freeze one semantic/time-domain group with bounded representative text."""
    first = events[0]
    ips = {event.source_ip for event in events if event.source_ip is not None}
    global_count = sum(ipaddress.ip_address(ip).is_global for ip in ips)
    times = [event.timestamp for event in events if event.timestamp is not None]
    notes = [COUNT_NOTE, *source_notes]
    examples = []
    for event in events:
        notes.extend(event.limitations)
        if len(examples) < MAX_EXAMPLES:
            raw = records[event.record_id].text
            example = _clip(raw, EXAMPLE_BYTES)
            examples.append(example)
            if example != raw:
                notes.append("representative example text clipped")
    if len(events) > MAX_EXAMPLES:
        notes.append("representative examples limited to 3 records")
    return PatternGroup(first.family, first.source_kind, first.source_identity,
        first.pattern_kind, first.signature, first.timestamp_basis, len(events),
        len(ips), global_count, len(ips) - global_count,
        min(times) if times else None, max(times) if times else None,
        tuple(event.record_id for event in events), tuple(examples), _limitations(notes))


def analyze_patterns(snapshot: EvidenceSnapshot) -> PatternInventory:
    """Project supplied evidence only; no acquisition, thresholds, or coverage I/O.

    Canonical source/family analyses union configured aliases. Within each pair,
    backend record identities give a deterministic order independent of text or
    chronology. Recognized records outside the aware UTC window are counted as
    excluded, separately from ignored/unrecognized input.
    """
    records = {record.identity: record for record in snapshot.records}
    pairs = {}
    for row in sorted(snapshot.sources, key=lambda row: (row.source.kind, row.source.identity)):
        source = row.source
        identity = (source.resolved_path or source.identity) if source.kind == "file" else source.identity
        for family in source.families:
            pairs.setdefault((source.kind, identity, family), []).append(row)
    events, analyses = [], []
    for key, rows in sorted(pairs.items()):
        recognized, analysis = _analyze_pair(key, rows, records, snapshot)
        events.extend(recognized)
        analyses.append(analysis)
    events.sort(key=lambda event: (event.family, event.source_kind, event.source_identity,
                                  event.pattern_kind, event.signature, event.timestamp_basis,
                                  _record_order(event.record_id)))
    notes = {(row.source_kind, row.source_identity, row.family): row.limitations for row in analyses}
    grouped = {}
    for event in events:
        key = (event.family, event.source_kind, event.source_identity,
               event.pattern_kind, event.signature, event.timestamp_basis)
        grouped.setdefault(key, []).append(event)
    groups = tuple(_group(rows, records, notes[(key[1], key[2], key[0])])
                   for key, rows in sorted(grouped.items()))
    return PatternInventory(snapshot, tuple(events), groups, tuple(analyses))
