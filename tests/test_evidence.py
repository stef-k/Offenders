"""Bounded acquisition contracts using temporary files and synthetic journal output."""
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import offenders_evidence as evidence
from offenders_fail2ban import CommandFailure, CommandResult
from offenders_host import HostInventory, SourceHealth
from offenders_sources import LogSource, LogSourceInventory, SourceAssociation

NOW = datetime(2026, 9, 27, 12, 30, 15, 123456, tzinfo=timezone.utc)
HOST = HostInventory((), (), *(SourceHealth("successful"),) * 3)


def inventory(*sources):
    """Supply discovery facts without executing discovery."""
    return LogSourceInventory(HOST, tuple(sources), ())


def file_source(path, identity=None):
    """Keep a configured alias separate from its discovery-resolved target."""
    return LogSource("file", identity or str(path), "readable", resolved_path=str(path))


def journal(cursor="cursor", message="raw message", **fields):
    """Build one allowlisted JSON entry, retaining overrides for malformed cases."""
    entry = {"__CURSOR": cursor, "__REALTIME_TIMESTAMP": "1000001", "MESSAGE": message}
    entry.update(fields)
    return json.dumps(entry)


def collector():
    """Use a fixed aware collection clock, independent of file timestamps."""
    return evidence.EvidenceCollector(utcnow=lambda: NOW)


class FileEvidenceTests(unittest.TestCase):
    """Real bounded file reads, alias identities, rotations, and unsafe leaf types."""

    def test_tail_offsets_raw_text_aliases_and_plain_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "current"
            path.write_bytes(b"discard this prefix\nidentical\nidentical\nlast\r")
            Path(str(path) + ".1").write_bytes(b"older\n")
            association = SourceAssociation("ssh", "active", "supplied")
            source = replace(file_source(path), associations=(association,))
            alias = file_source(path, "configured-alias")
            real_read = os.read
            with patch.object(evidence, "FILE_BYTES", 30), \
                    patch.object(evidence.os, "read", wraps=real_read) as read:
                snapshot = collector().collect(inventory(source, alias))
            self.assertTrue(all(call.args[1] <= 30 for call in read.call_args_list))
            self.assertEqual(len(snapshot.records), 4)
            self.assertEqual(sorted(row.text for row in snapshot.records),
                             ["identical", "identical", "last\r", "older"])
            self.assertTrue(all(len(row.sources) == 2 for row in snapshot.records))
            self.assertTrue(all(row.timestamp is None for row in snapshot.records))
            info = path.stat()
            identities = {row.identity for row in snapshot.records}
            self.assertIn(("file", info.st_dev, info.st_ino, 20), identities)
            self.assertIn(("file", info.st_dev, info.st_ino, 30), identities)
            result = next(row for row in snapshot.sources if row.source is source)
            self.assertIs(result.source.associations[0], association)
            self.assertTrue(result.truncated)
            by_id = {row.identity: row for row in snapshot.records}
            self.assertEqual([by_id[key].text for key in result.record_ids],
                             ["identical", "identical", "last\r", "older"])

    def test_binary_lossy_text_cap_and_compressed_limitation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "log"
            path.write_bytes(b"valid\n\xff\n" + b"x" * 20)
            rotation = Path(str(path) + ".1")
            rotation.write_bytes(b"binary\0data")
            with patch.object(evidence, "RECORD_BYTES", 8):
                snapshot = collector().collect(inventory(file_source(path)))
            self.assertEqual(len(snapshot.records), 3)
            self.assertTrue(any(row.text_truncated for row in snapshot.records))
            self.assertIn("�", [row.text for row in snapshot.records])
            self.assertEqual(snapshot.sources[0].state, "partial")
            self.assertIn("binary", " ".join(snapshot.sources[0].limitations))
            rotation.unlink()
            Path(str(rotation) + ".gz").write_bytes(b"not decompressed")
            snapshot = collector().collect(inventory(file_source(path)))
            self.assertIn("compressed rotation not collected", snapshot.sources[0].limitations)

    def test_stale_missing_permission_nonregular_and_retargeted_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.write_text("original")
            configured = root / "configured"
            configured.symlink_to(root / "missing")
            source = file_source(target, str(configured))
            self.assertEqual(collector().collect(inventory(source)).records[0].text, "original")
            target.unlink()
            os.mkfifo(target)
            sources = (source, file_source(root), file_source(root / "missing"),
                       LogSource("file", str(configured), "readable"))
            snapshot = collector().collect(inventory(*sources))
            self.assertTrue(all(row.state == "unavailable" for row in snapshot.sources))
            target.unlink()
            target.symlink_to(root)
            self.assertEqual(collector().collect(inventory(source)).sources[0].state, "unavailable")
            with patch.object(evidence.os, "open", side_effect=PermissionError("denied")):
                result = collector().collect(inventory(source)).sources[0]
            self.assertEqual(result.state, "unavailable")
            self.assertIn("denied", " ".join(result.limitations))

    def test_source_and_global_caps_prioritize_current_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            first, second = Path(directory) / "a", Path(directory) / "b"
            first.write_text("a0\na1\na2\n")
            second.write_text("b0\nb1\n")
            Path(str(first) + ".1").write_text("old\n")
            sources = inventory(file_source(first), file_source(second))
            with patch.object(evidence, "SOURCE_LINES", 2), patch.object(evidence, "MAX_RECORDS", 4):
                snapshot = collector().collect(sources)
            self.assertEqual({row.text for row in snapshot.records}, {"a1", "a2", "b0", "b1"})
            self.assertTrue(snapshot.truncated)
            with patch.object(evidence, "MAX_TEXT_BYTES", 3):
                snapshot = collector().collect(sources)
            self.assertEqual([row.text for row in snapshot.records], ["a2"])
            self.assertTrue(all(row.truncated for row in snapshot.sources))
            with patch.object(evidence, "SOURCE_FILE_BYTES", 4):
                snapshot = collector().collect(inventory(file_source(first)))
            self.assertEqual([row.text for row in snapshot.records], ["a2"])
            self.assertTrue(snapshot.truncated)

    def test_missing_current_keeps_rotation_and_other_source_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path, other = Path(directory) / "missing", Path(directory) / "other"
            Path(str(path) + ".1").write_text("older")
            other.write_text("current")
            snapshot = collector().collect(inventory(file_source(path), file_source(other)))
        self.assertEqual({row.text for row in snapshot.records}, {"older", "current"})
        self.assertEqual([row.state for row in snapshot.sources], ["partial", "collected"])

    def test_large_file_reads_only_tail_and_empty_file_is_collected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large"
            with path.open("wb") as stream:
                stream.seek(2 * evidence.FILE_BYTES)
                stream.write(b"prefix\nnewest")
            real_seek, real_read = os.lseek, os.read
            with patch.object(evidence.os, "lseek", wraps=real_seek) as seek, \
                    patch.object(evidence.os, "read", wraps=real_read) as read:
                snapshot = collector().collect(inventory(file_source(path)))
            self.assertGreater(seek.call_args.args[1], 0)
            self.assertEqual(read.call_args.args[1], evidence.FILE_BYTES)
            self.assertEqual(snapshot.records, ())  # Sparse NUL-containing tail is unsupported.
            self.assertEqual(snapshot.sources[0].state, "partial")
            path.write_bytes(b"")
            snapshot = collector().collect(inventory(file_source(path)))
            self.assertEqual(snapshot.records, ())
            self.assertEqual(snapshot.sources[0].state, "collected")


class JournalEvidenceTests(unittest.TestCase):
    """Command shape, exact identities, malformed entries, and bounded retention."""

    def test_command_cursor_union_local_identity_and_bad_entries(self):
        valid = journal(_SYSTEMD_UNIT="a.service", IGNORED="not retained")
        no_cursor = journal(cursor="")
        output = "\n".join((valid, no_cursor, "{bad", journal(MESSAGE=[1, 2]),
                            journal(__REALTIME_TIMESTAMP="invalid"), json.dumps({"MESSAGE": "x"})))
        sources = inventory(LogSource("journal", "a.service", "readable"),
                            LogSource("journal", "b.service", "readable"))
        with patch.object(evidence, "run_host_command", return_value=CommandResult(0, output, "")) as run:
            snapshot = collector().collect(sources)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[0].args[0], [
            "journalctl", "--quiet", "--no-pager", "--utc", "--unit", "a.service",
            "--since", "2026-09-26 12:30:15.123456 UTC", "--lines", "1000", "--output=json",
            "--output-fields=" + ",".join(evidence.JOURNAL_FIELDS)])
        self.assertTrue(all(call.kwargs == {"timeout": 8, "sudo": False} for call in run.call_args_list))
        self.assertEqual(len(snapshot.records), 3)
        stable = next(row for row in snapshot.records if row.stable)
        self.assertEqual(stable.identity, ("journal", "cursor"))
        self.assertEqual(len(stable.sources), 2)
        self.assertEqual(stable.timestamp, datetime(1970, 1, 1, 0, 0, 1, 1, tzinfo=timezone.utc))
        self.assertNotIn("IGNORED", dict(stable.metadata))
        self.assertTrue(all(row.state == "partial" for row in snapshot.sources))
        self.assertEqual(snapshot.source_inventory, sources)
        with self.assertRaises(FrozenInstanceError):
            stable.text = "mutate"

    def test_exact_query_limit_is_explicit_and_unicode_line_separator_is_raw(self):
        output = json.dumps({"__CURSOR": "one", "__REALTIME_TIMESTAMP": "1",
                             "MESSAGE": "raw\u2028text"}, ensure_ascii=False) + "\n"
        sources = inventory(LogSource("journal", "unit", "readable"))
        with patch.object(evidence, "run_host_command", return_value=CommandResult(0, output, "")), \
                patch.object(evidence, "JOURNAL_LINES", 1):
            snapshot = collector().collect(sources)
        self.assertEqual(snapshot.records[0].text, "raw\u2028text")
        self.assertTrue(snapshot.truncated)
        self.assertEqual(snapshot.sources[0].state, "partial")

    def test_failures_zero_entries_and_custom_window(self):
        sources = inventory(LogSource("journal", "unit", "readable"))
        for failure in (None, *CommandFailure):
            with self.subTest(failure=failure), patch.object(evidence, "run_host_command",
                    return_value=CommandResult(None, "", "x" * 800 if failure else "", failure)) as run:
                snapshot = collector().collect(sources, lookback=timedelta(hours=2))
            result = snapshot.sources[0]
            self.assertEqual(result.state, "unavailable" if failure else "collected")
            self.assertEqual(result.failure, failure)
            self.assertEqual(snapshot.records, ())
            self.assertEqual(snapshot.requested_since, NOW - timedelta(hours=2))
            self.assertIn("2026-09-27 10:30:15.123456 UTC", run.call_args.args[0])
            self.assertTrue(all(len(item.encode()) <= evidence.DETAIL_BYTES for item in result.limitations))

    def test_stdout_entry_text_caps_and_deterministic_timestamp_order(self):
        lines = [journal(str(index), "é" * 20, __REALTIME_TIMESTAMP=str(100 - index))
                 for index in range(6)]
        sources = inventory(LogSource("journal", "unit", "readable"))
        with patch.object(evidence, "run_host_command", return_value=CommandResult(0, "\n".join(lines), "")), \
                patch.object(evidence, "JOURNAL_BYTES", len("\n".join(lines[-4:]).encode()) + 5), \
                patch.object(evidence, "JOURNAL_LINES", 2), patch.object(evidence, "RECORD_BYTES", 7):
            snapshot = collector().collect(sources)
            repeated = collector().collect(sources)
        self.assertEqual(snapshot, repeated)
        self.assertEqual([row.identity for row in snapshot.records], [("journal", "5"), ("journal", "4")])
        self.assertTrue(all(len(row.text.encode()) <= 7 and row.text_truncated for row in snapshot.records))
        self.assertTrue(snapshot.truncated)
        self.assertIn("journal entry count capped", snapshot.sources[0].limitations)
        self.assertIn("journal stdout tail capped", snapshot.sources[0].limitations)


class InvocationTests(unittest.TestCase):
    """Identity cache and explicit-only source eligibility."""

    def test_single_entry_cache_identity_expiry_force_and_failed_snapshot(self):
        sources = inventory(LogSource("journal", "unit", "readable"))
        clock = [0.0]
        instance = evidence.EvidenceCollector(monotonic=lambda: clock[0], utcnow=lambda: NOW)
        with patch.object(evidence, "run_host_command",
                          return_value=CommandResult(None, "", "", CommandFailure.TIMEOUT)) as run:
            first = instance.collect(sources)
            self.assertIs(instance.collect(sources), first)
            clock[0] = 299.0
            self.assertIs(instance.collect(sources), first)
            self.assertEqual(run.call_count, 1)
            clock[0] = 300.0
            self.assertIsNot(instance.collect(sources), first)
            instance.collect(sources, force=True)
            instance.collect(replace(sources))
            instance.collect(sources)
            instance.collect(sources, lookback=timedelta(hours=1))
            self.assertEqual(run.call_count, 6)
        for value in (timedelta(0), timedelta(seconds=-1), timedelta(days=8), float("inf"), float("nan")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                instance.collect(sources, lookback=value)

    def test_skipped_sources_never_read_and_keep_upstream_identity(self):
        sources = inventory(*(LogSource("file", state, state, detail="upstream reason")
                              for state in ("missing", "unreadable", "unsupported", "unavailable")),
                            LogSource("unknown", "future", "readable"))
        with patch.object(evidence.os, "open", side_effect=AssertionError("file I/O")), \
                patch.object(evidence, "run_host_command", side_effect=AssertionError("command I/O")):
            snapshot = collector().collect(sources)
        self.assertIs(snapshot.source_inventory, sources)
        self.assertEqual(len(snapshot.sources), 5)
        self.assertTrue(all(row.state == "skipped" for row in snapshot.sources))
        self.assertTrue(all(any(row.source is source for source in sources.sources) for row in snapshot.sources))
        self.assertFalse(snapshot.truncated)
        self.assertEqual(snapshot.records, ())
