"""Explicit bounded evidence acquisition; offenders_patterns owns event semantics."""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
import json
import os
import stat
import time
from typing import Callable

from offenders_fail2ban import CommandFailure, run_host_command
from offenders_sources import LogSource, LogSourceInventory

# Budgets count UTF-8 text bytes; file input budgets count original bytes.
MAX_RECORDS = 10_000
MAX_TEXT_BYTES = 8 * 1024 * 1024
RECORD_BYTES = 16 * 1024
FILE_BYTES = 256 * 1024
SOURCE_FILE_BYTES = 512 * 1024
SOURCE_LINES = 2_000
JOURNAL_BYTES = 4 * 1024 * 1024
JOURNAL_LINES = 1_000
DETAIL_BYTES = 300
MAX_DIAGNOSTICS = 16
CACHE_TTL = 300
JOURNAL_FIELDS = ("__CURSOR", "__REALTIME_TIMESTAMP", "MESSAGE", "_SYSTEMD_UNIT",
                  "SYSLOG_IDENTIFIER", "_COMM", "_PID", "PRIORITY")
SourceKey = tuple[str, str]
RecordKey = tuple[str | int, ...]


def _clip(text: str, limit: int) -> str:
    """Bound encoded text without splitting a Unicode character."""
    return text.encode("utf-8", errors="replace")[:limit].decode("utf-8", errors="ignore")


@dataclass(frozen=True)
class EvidenceRecord:
    """One backend identity, with exact producing source keys into the inventory."""

    identity: RecordKey
    stable: bool
    sources: tuple[SourceKey, ...]
    text: str
    timestamp: datetime | None = None
    metadata: tuple[tuple[str, str], ...] = ()
    text_truncated: bool = False


@dataclass(frozen=True)
class SourceResult:
    """Exact upstream associations and explicit bounded acquisition health."""

    source: LogSource
    state: str
    record_ids: tuple[RecordKey, ...]
    truncated: bool
    limitations: tuple[str, ...]
    failure: CommandFailure | None = None


@dataclass(frozen=True)
class EvidenceSnapshot:
    """Completed immutable evidence; files have no inferred event chronology."""

    source_inventory: LogSourceInventory
    collected_at: datetime
    lookback: timedelta
    requested_since: datetime
    records: tuple[EvidenceRecord, ...]
    sources: tuple[SourceResult, ...]
    truncated: bool
    limitations: tuple[str, ...]


@dataclass
class _SourceWork:
    """Collection-local state, frozen before publishing or caching."""

    source: LogSource
    state: str = "collected"
    ids: dict[RecordKey, tuple] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)
    truncated: bool = False
    failure: CommandFailure | None = None
    input_bytes: int = 0
    lines: int = 0

    @property
    def key(self) -> SourceKey:
        """Match the upstream source identity without flattening associations."""
        return self.source.kind, self.source.identity

    def note(self, message: str, *, truncated: bool = False) -> None:
        """Retain bounded unique diagnostics and never lose partial status."""
        message = _clip(message, DETAIL_BYTES)
        if message not in self.limitations and len(self.limitations) < MAX_DIAGNOSTICS:
            self.limitations.append(message)
        self.truncated |= truncated
        if self.state == "collected":
            self.state = "partial"

    def freeze(self) -> SourceResult:
        """Publish physical generation/offset or structured timestamp ordering."""
        ids = tuple(sorted(self.ids, key=lambda identity: self.ids[identity]))
        return SourceResult(self.source, self.state, ids, self.truncated,
                            tuple(self.limitations), self.failure)


class _Budget:
    """Shared retained-record budget and exact backend identity deduplication."""

    def __init__(self) -> None:
        self.records: dict[RecordKey, EvidenceRecord] = {}
        self.text_bytes = 0
        self.stopped = False

    def add(self, record: EvidenceRecord, work: _SourceWork, order: tuple) -> bool:
        """Union aliases before charging the logical-record/text budget."""
        previous = self.records.get(record.identity)
        if previous is not None:
            self.records[record.identity] = replace(
                previous, sources=tuple(sorted(set(previous.sources + record.sources))))
            work.ids[record.identity] = order
            return True
        size = len(record.text.encode("utf-8"))
        if self.stopped or len(self.records) >= MAX_RECORDS or self.text_bytes + size > MAX_TEXT_BYTES:
            self.stopped = True
            work.note("global evidence budget reached", truncated=True)
            return False
        self.records[record.identity] = record
        self.text_bytes += size
        work.ids[record.identity] = order
        return True


def _tail(path: str, limit: int) -> tuple[os.stat_result, int, bytes]:
    """Open the resolved leaf without following symlinks; never read a FIFO/device."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("collection target is no longer a regular file")
        start = max(0, info.st_size - limit)
        os.lseek(descriptor, start, os.SEEK_SET)
        data = os.read(descriptor, min(limit, info.st_size))
        if len(data) != info.st_size - start:
            raise OSError("file changed or short read during tail collection")
        return info, start, data
    finally:
        os.close(descriptor)


def _file_records(info: os.stat_result, start: int, data: bytes,
                  generation: int, work: _SourceWork, budget: _Budget) -> None:
    """Preserve byte offsets and raw line bodies; favor the newest complete lines."""
    if start:
        work.note("file tail starts after older evidence", truncated=True)
    if b"\0" in data:
        work.note("binary/unsupported file tail (NUL byte)")
        return
    if start:
        boundary = data.find(b"\n")
        if boundary < 0:
            return
        start += boundary + 1
        data = data[boundary + 1:]
    # Split only LF; retain CR and all other raw text characters.
    lines = data.split(b"\n")
    if lines[-1] == b"":
        lines.pop()
    offsets = []
    for line in lines:
        offsets.append(start)
        start += len(line) + 1
    for offset, line in reversed(list(zip(offsets, lines))):
        if work.lines >= SOURCE_LINES:
            work.note("file source line budget reached", truncated=True)
            break
        work.lines += 1
        try:
            text = line.decode("utf-8")
        except UnicodeDecodeError:
            text = line.decode("utf-8", errors="replace")
            work.note("lossy UTF-8 file decoding")
        clipped = _clip(text, RECORD_BYTES)
        shortened = clipped != text
        if shortened:
            work.note("record text capped", truncated=True)
        identity = ("file", info.st_dev, info.st_ino, offset)
        record = EvidenceRecord(identity, True, (work.key,), clipped, text_truncated=shortened)
        if not budget.add(record, work, (generation, info.st_dev, info.st_ino, offset)):
            break


def _file(work: _SourceWork, budget: _Budget, generation: int) -> None:
    """Collect current then one plain rotation, preserving independent failures."""
    path = work.source.resolved_path
    if not path:
        work.state = "unavailable"
        work.note("readable source lacks resolved_path; stale source inventory")
        return
    if budget.stopped or work.lines >= SOURCE_LINES or work.input_bytes >= SOURCE_FILE_BYTES:
        work.note("older/file evidence omitted by budget", truncated=True)
        return
    target = path + (".1" if generation else "")
    try:
        info, start, data = _tail(target, min(FILE_BYTES, SOURCE_FILE_BYTES - work.input_bytes))
    except FileNotFoundError as error:
        if generation:
            try:
                os.lstat(path + ".1.gz")
            except FileNotFoundError:
                return
            except OSError as compressed_error:
                work.note(f"compressed rotation metadata unavailable: {compressed_error}")
                return
            work.note("compressed rotation not collected")
            return
        work.state = "unavailable"
        work.note(f"current file unavailable: {error}")
        return
    except OSError as error:
        if not generation:
            work.state = "unavailable"
        work.note(f"file generation {generation} unavailable: {error}")
        return
    work.input_bytes += len(data)
    _file_records(info, start, data, generation, work, budget)
    if work.ids and work.state == "unavailable":
        work.state = "partial"


def _journal_entry(line: str, index: int, work: _SourceWork) -> EvidenceRecord | None:
    """Parse allowlisted string fields only, preserving exact cursor identities."""
    try:
        entry = json.loads(line)
        if not isinstance(entry, dict) or any(
            not isinstance(entry[key], str) for key in JOURNAL_FIELDS if key in entry
        ):
            raise ValueError("unsupported journal field form")
        message = entry.get("MESSAGE")
        micros = entry.get("__REALTIME_TIMESTAMP", "")
        if message is None or not micros.isascii() or not micros.isdecimal():
            raise ValueError("missing message or invalid timestamp")
        timestamp = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=int(micros))
        cursor = entry.get("__CURSOR")
        if cursor and len(cursor.encode("utf-8")) > RECORD_BYTES:
            raise ValueError("oversized journal cursor")
    except (ValueError, TypeError, OverflowError, RecursionError):
        work.note("malformed journal entry/message/timestamp or unsupported field form")
        return None
    identity = ("journal", cursor) if cursor else ("journal-local", *work.key, index)
    if not cursor:
        work.note("journal entry lacks stable cursor")
    text = _clip(message, RECORD_BYTES)
    shortened = text != message
    metadata = tuple((key, _clip(entry[key], DETAIL_BYTES)) for key in JOURNAL_FIELDS
                     if key in entry and key != "MESSAGE")
    if shortened or any(value != entry[key] for key, value in metadata):
        work.note("journal text/metadata capped", truncated=True)
    return EvidenceRecord(identity, bool(cursor), (work.key,), text, timestamp, metadata, shortened)


def _journal(work: _SourceWork, budget: _Budget, since: datetime) -> None:
    """One non-sudo bounded query; runner captures stdout before our parse bounds."""
    result = run_host_command(
        ["journalctl", "--quiet", "--no-pager", "--utc", "--unit", work.source.identity,
         "--since", since.strftime("%Y-%m-%d %H:%M:%S.%f UTC"),
         "--lines", str(JOURNAL_LINES), "--output=json",
         "--output-fields=" + ",".join(JOURNAL_FIELDS)], timeout=8, sudo=False,
    )
    if result.failure:
        work.state = "unavailable"
        work.failure = result.failure
        work.note(result.stderr or result.detail or result.failure.value)
        return
    # Slice characters before encoding, so bounding adds at most 4x the byte cap.
    tail = result.stdout[-JOURNAL_BYTES:].encode("utf-8", errors="replace")
    cut = len(result.stdout) > JOURNAL_BYTES or len(tail) > JOURNAL_BYTES
    tail = tail[-JOURNAL_BYTES:]
    if cut:
        work.note("journal stdout tail capped", truncated=True)
        tail = tail.partition(b"\n")[2]
    lines = tail.decode("utf-8", errors="replace").split("\n")
    if lines[-1] == "":
        lines.pop()
    if len(lines) >= JOURNAL_LINES:
        work.note("journal entry count capped", truncated=True)
    for index, line in reversed(list(enumerate(lines[-JOURNAL_LINES:]))):
        record = _journal_entry(line, index, work)
        if record is not None:
            if not budget.add(record, work, (record.timestamp, record.identity)):
                break


def _snapshot(inventory: LogSourceInventory, collected_at: datetime,
              lookback: timedelta) -> EvidenceSnapshot:
    """Collect all current sources before spending remaining budgets on rotations."""
    since = collected_at - lookback
    budget = _Budget()
    works = [_SourceWork(source) for source in sorted(
        inventory.sources, key=lambda source: (source.kind, source.identity))]
    for work in works:
        if work.source.state != "readable" or work.source.kind not in ("file", "journal"):
            work.state = "skipped"
            work.failure = work.source.failure
            reason = "unsupported kind" if work.source.kind not in ("file", "journal") else work.source.state
            work.note(f"{reason}/{work.source.kind}: {work.source.detail}")
        elif budget.stopped:
            work.note("global evidence budget reached", truncated=True)
        elif work.source.kind == "file":
            _file(work, budget, 0)
        else:
            _journal(work, budget, since)
    for work in works:
        if work.source.state == "readable" and work.source.kind == "file":
            _file(work, budget, 1)
    records = tuple(sorted(budget.records.values(), key=lambda record: (
        record.timestamp is None, record.timestamp or collected_at,
        record.sources[0] if record.timestamp is None else ("", ""), record.identity)))
    sources = tuple(work.freeze() for work in works)
    limitations = tuple(f"{row.source.kind}:{row.source.identity}: {row.state}" for row in sources
                        if row.state != "collected")
    return EvidenceSnapshot(inventory, collected_at, lookback, since, records, sources,
                            any(row.truncated for row in sources), limitations)


class EvidenceCollector:
    """Manual collection with one identity-keyed five-minute monotonic cache.

    Lookback is a positive timedelta up to seven days. File timestamps remain
    uninterpreted. Both partial and successful completed snapshots are cached.
    """

    def __init__(self, *, monotonic: Callable[[], float] = time.monotonic,
                 utcnow: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        self._monotonic = monotonic
        self._utcnow = utcnow
        self._cached: EvidenceSnapshot | None = None
        self._completed_at = 0.0

    def collect(self, source_inventory: LogSourceInventory, *, force: bool = False,
                lookback: timedelta = timedelta(hours=24)) -> EvidenceSnapshot:
        """Return the same immutable cached object without any acquisition I/O."""
        if not isinstance(lookback, timedelta) or not timedelta(0) < lookback <= timedelta(days=7):
            raise ValueError("lookback must be a positive timedelta up to seven days")
        cached = self._cached
        if (not force and cached is not None and cached.source_inventory is source_inventory
                and cached.lookback == lookback and self._monotonic() - self._completed_at < CACHE_TTL):
            return cached
        collected_at = self._utcnow()
        if collected_at.tzinfo is None or collected_at.utcoffset() is None:
            raise ValueError("collection clock must return a timezone-aware datetime")
        snapshot = _snapshot(source_inventory, collected_at.astimezone(timezone.utc), lookback)
        self._cached = snapshot
        self._completed_at = self._monotonic()
        return snapshot
