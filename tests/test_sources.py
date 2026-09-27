"""Local metadata and synthetic snapshot contracts; no host logs or daemons."""
from dataclasses import FrozenInstanceError
from pathlib import Path
import tempfile
import unittest
from unittest.mock import call, patch

from offenders_fail2ban import CommandFailure, CommandResult
from offenders_host import HostInventory, Listener, ServiceObservation, SourceHealth, UnitState
from offenders_sources import discover_log_sources, probe_file, probe_journal


class FileSourceTests(unittest.TestCase):
    """Exercise real filesystem metadata with access/error outcomes controlled."""

    def test_metadata_states_and_symlink_identity_without_content_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            regular = root / "log"
            regular.write_text("must never be collected")
            link = root / "alias"
            link.symlink_to(regular)
            broken = root / "broken"
            broken.symlink_to(root / "missing")
            with patch("builtins.open", side_effect=AssertionError("content read")), \
                    patch("pathlib.Path.open", side_effect=AssertionError("content read")):
                source = probe_file(str(regular))
                self.assertEqual(source.state, "readable")
                self.assertTrue(source.is_regular)
                self.assertTrue(source.directly_readable)
                alias = probe_file(str(link))
                self.assertEqual(alias.identity, str(link))
                self.assertEqual(alias.resolved_path, str(regular))
                self.assertEqual(alias.state, "readable")
                self.assertEqual(probe_file(str(root)).state, "unsupported")
                self.assertEqual(probe_file(str(root / "missing")).state, "missing")
                self.assertEqual(probe_file(str(broken)).state, "missing")
                with patch("offenders_sources.os.access", return_value=False):
                    denied = probe_file(str(regular))
                self.assertEqual(denied.state, "unreadable")
                self.assertTrue(denied.is_regular)
                self.assertFalse(denied.directly_readable)

    def test_metadata_errors_are_bounded_and_not_missing(self):
        for error in (PermissionError("denied" * 200), OSError("I/O failure" * 200)):
            with self.subTest(error=type(error)), \
                    patch("offenders_sources.os.stat", side_effect=error):
                source = probe_file("/candidate")
            self.assertEqual(source.state, "unavailable")
            self.assertIsNone(source.is_regular)
            self.assertEqual(len(source.detail), 300)


class JournalSourceTests(unittest.TestCase):
    """Retain runner failures and never infer historical entries from success."""

    def test_exact_probe_and_failure_categories(self):
        for failure in (None, *CommandFailure):
            result = CommandResult(0 if failure is None else None, "not retained", "",
                                   failure, "detail" * 100 if failure else "")
            with self.subTest(failure=failure), \
                    patch("offenders_sources.run_host_command", return_value=result) as run:
                source = probe_journal("ssh.service")
            run.assert_called_once_with(
                ["journalctl", "--quiet", "--no-pager", "--unit", "ssh.service", "--lines=0"],
                timeout=8, sudo=False,
            )
            self.assertEqual(source.state, "unavailable" if failure else "readable")
            self.assertEqual(source.failure, failure)
            self.assertNotIn("not retained", repr(source))
            self.assertLessEqual(len(source.detail), 300)


class SourceInventoryTests(unittest.TestCase):
    """One supplied host snapshot owns all service/listener association evidence."""

    def test_deduplication_inactive_process_only_and_unknown_evidence(self):
        known = Listener("tcp", "0.0.0.0", "0.0.0.0", None, 22, "non_loopback")
        unknown = Listener("tcp", "0.0.0.0", "0.0.0.0", None, 443, "non_loopback")
        loaded = UnitState("ssh.service", "loaded", "inactive", "dead")
        health = SourceHealth("partial", diagnostics=("owners missing",))
        services = (
            ServiceObservation("vsftpd", "listening_non_loopback", (known,), ()),
            ServiceObservation("ssh", "installed_inactive", (), (loaded, loaded)),
            ServiceObservation("ssh", "installed_inactive", (), (loaded,)),
            ServiceObservation("caddy", "installed_inactive", (),
                               (UnitState("caddy.service", "masked", "inactive", "dead"),)),
        )
        host = HostInventory((known, unknown), services, health, health, health)
        with patch("offenders_sources.os.stat", side_effect=FileNotFoundError("missing")) as metadata, \
                patch("offenders_sources.run_host_command", return_value=CommandResult(0, "", "")) as run, \
                patch("offenders_host.discover_host_inventory", side_effect=AssertionError("rediscovery")), \
                patch("builtins.open", side_effect=AssertionError("content read")):
            inventory = discover_log_sources(host)
            self.assertEqual(metadata.call_args_list,
                             [call("/var/log/auth.log"), call("/var/log/vsftpd.log")])
            run.assert_called_once_with(
                ["journalctl", "--quiet", "--no-pager", "--unit", "ssh.service", "--lines=0"],
                timeout=8, sudo=False,
            )
            reversed_host = HostInventory(host.listeners, tuple(reversed(services)), health, health, health)
            reordered = discover_log_sources(reversed_host)
        self.assertEqual(inventory.sources, reordered.sources)
        self.assertIs(inventory.host_inventory, host)
        self.assertEqual(inventory.unassociated_listeners, (unknown,))
        self.assertEqual([(s.kind, s.identity) for s in inventory.sources], [
            ("file", "/var/log/auth.log"), ("file", "/var/log/vsftpd.log"),
            ("journal", "ssh.service"),
        ])
        shared = inventory.sources[0]
        self.assertEqual(shared.state, "missing")
        self.assertEqual(shared.families, ("ssh", "vsftpd"))
        self.assertEqual(shared.associations[0].service_state, "installed_inactive")
        self.assertEqual(shared.associations[0].reason, "fixed standard file candidate: /var/log/auth.log")
        self.assertEqual(inventory.sources[-1].state, "readable")
        self.assertEqual(inventory.sources[-1].associations[0].reason,
                         "observed loaded systemd unit: ssh.service")
        with self.assertRaises(FrozenInstanceError):
            shared.state = "readable"

    def test_absent_families_do_not_trigger_probes(self):
        health = SourceHealth("successful")
        host = HostInventory((), (), health, health, health)
        with patch("offenders_sources.os.stat") as metadata, \
                patch("offenders_sources.run_host_command") as run:
            self.assertEqual(discover_log_sources(host).sources, ())
        metadata.assert_not_called()
        run.assert_not_called()
