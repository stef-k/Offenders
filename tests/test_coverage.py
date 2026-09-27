"""Synthetic runtime/config coverage contracts; never access a daemon or host logs."""
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import call, patch

from offenders_coverage import discover_coverage, discover_static
from offenders_fail2ban import (
    CommandFailure, CommandResult, Fail2BanParseError, JailSources,
    get_jail_sources, parse_journalmatch, parse_logpaths,
)
from offenders_host import HostInventory, Listener, ServiceObservation, SourceHealth
from offenders_sources import LogSource, LogSourceInventory, SourceAssociation


def snapshot(*sources):
    """Supply immutable source/host evidence, including deliberately missing identity."""
    health = SourceHealth("partial", diagnostics=("upstream evidence retained",))
    unknown = Listener("tcp", "*", None, None, 8080, "non_loopback")
    host = HostInventory((unknown,), (ServiceObservation("caddy", "installed_inactive", (), ()),),
                         health, health, health)
    return LogSourceInventory(host, tuple(sources), (unknown,))


def source(identity, family="ssh", kind="file"):
    """Use the real upstream association model rather than a parallel fixture schema."""
    return LogSource(kind, identity, "missing", (SourceAssociation(family, "installed_inactive", "fixture"),))


class RuntimeSourcesTests(unittest.TestCase):
    """Stable 1.0.2 beautifier forms and original command/parse error preservation."""

    def test_parsers_distinguish_empty_malformed_and_concrete_evidence(self):
        self.assertEqual(parse_logpaths("No file is currently monitored\n"), ())
        self.assertEqual(parse_journalmatch("No journal match filter set\n"), "")
        self.assertEqual(parse_logpaths("Current monitored log file(s):\n|- /a\n`- /b"), ("/a", "/b"))
        self.assertEqual(parse_logpaths("Current monitored log file(s):\n\\- /a"), ("/a",))
        expression = "_SYSTEMD_UNIT=ssh.service + SYSLOG_IDENTIFIER=sshd"
        self.assertEqual(parse_journalmatch("Current match filter:\n" + expression), expression)
        for parser, outputs in ((parse_logpaths, ("", "Current monitored log file(s):", "oops",
                                                "Current monitored log file(s):\n/a")),
                                (parse_journalmatch, ("", "Current match filter:", "oops",
                                                     "Current match filter:\n+", "Current match filter:\noops"))):
            for output in outputs:
                with self.subTest(output=output), self.assertRaises(Fail2BanParseError):
                    parser(output)
        for parser in (parse_logpaths, parse_journalmatch):
            with self.assertRaises(Fail2BanParseError):
                parser("x" * 65537)

    def test_independent_queries_use_existing_boundary_and_keep_failures(self):
        failed = CommandResult(1, "failed stdout", "denied", CommandFailure.NONZERO_EXIT)
        ok = CommandResult(0, "Current match filter:\n_SYSTEMD_UNIT=ssh.service", "")
        with patch("offenders_fail2ban.run_host_command", side_effect=[failed, ok]) as run:
            result = get_jail_sources("custom")
        self.assertEqual(run.call_args_list, [
            call(["fail2ban-client", "get", "custom", "logpath"], timeout=8, sudo=True),
            call(["fail2ban-client", "get", "custom", "journalmatch"], timeout=8, sudo=True),
        ])
        self.assertIs(result.errors["logpath"].result, failed)
        self.assertIsNone(result.logpaths)
        self.assertEqual(result.journal_units, ("ssh.service",))
        with patch("offenders_fail2ban.run_host_command", side_effect=[
                CommandResult(0, "Current monitored log file(s):\n`- /a", ""), CommandResult(0, "oops", "")]):
            result = get_jail_sources("custom")
        self.assertEqual(result.logpaths, ("/a",))
        self.assertIsInstance(result.errors["journalmatch"], Fail2BanParseError)


class ConfigTests(unittest.TestCase):
    """Real temporary configuration files exercise bounded conservative inventory."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "jail.d").mkdir()
        (self.root / "filter.d").mkdir()

    def write(self, name, content):
        """Write only fixture-owned config, never production configuration."""
        (self.root / name).write_text(content)

    def test_effective_precedence_custom_names_defaults_and_filter_overlay(self):
        self.write("jail.conf", "[DEFAULT]\nenabled=no\nfilter=%(__name__)s[mode=normal]\n"
                   "[custom]\nlogpath=/first\n[odd]\nenabled=maybe\nfilter=%(missing)s\n"
                   "[enabled]\nenabled=yes\n[interpolated]\nlogpath=%(auth_log)s\n")
        self.write("jail.d/10.conf", "[DEFAULT]\nenabled=true\n[custom]\nlogpath=/second\nenabled=off\n")
        self.write("jail.d/20.conf", "[custom]\nlogpath=/third\n")
        self.write("jail.local", "[custom]\nlogpath=/fourth\n")
        self.write("jail.d/10.local", "[custom]\nlogpath=/fifth\n")
        self.write("jail.d/20.local", "[custom]\nlogpath=/var/log/site/*.log\nbackend=auto\n")
        self.write("filter.d/custom.conf", "[Definition]\njournalmatch=_SYSTEMD_UNIT=old.service\nfailregex=ignored\n")
        self.write("filter.d/custom.local", "[Definition]\njournalmatch=_SYSTEMD_UNIT=ssh.service\n")
        self.write("filter.d/local-only.local", "[Definition]\njournalmatch=_SYSTEMD_UNIT=local.service\n")
        result = discover_static(self.root)
        jails = {row.name: row for row in result.jails}
        self.assertFalse(jails["custom"].enabled)
        self.assertTrue(jails["enabled"].enabled)
        self.assertIsNone(jails["odd"].enabled)
        self.assertIsNone(jails["odd"].filter_stem)
        self.assertEqual(jails["custom"].filter_stem, "custom")
        self.assertEqual(jails["custom"].patterns, ("/var/log/site/*.log",))
        self.assertEqual(jails["custom"].backend, "auto")
        self.assertEqual(len(jails["custom"].fragments), 6)
        self.assertEqual(jails["interpolated"].patterns, ())
        self.assertTrue(jails["interpolated"].limitations)
        filters = {row.name: row for row in result.filters}
        self.assertEqual(filters["custom"].journal_units, ("ssh.service",))
        self.assertTrue(filters["local-only"].readable)
        self.assertFalse(result.limitations)

    def test_bounds_and_bad_overrides_prevent_false_disabled_or_negative(self):
        self.write("jail.conf", "[custom]\nenabled=false\nfilter=custom\nlogpath=/a\n")
        self.write("filter.d/custom.conf", "[Definition]\n")
        cases = (("MAX_CONFIG_FILES", 1), ("MAX_FILE_BYTES", 5), ("MAX_TOTAL_BYTES", 55))
        for constant, bound in cases:
            with self.subTest(constant=constant), patch("offenders_coverage." + constant, bound), \
                    patch("offenders_coverage.get_jail_list", return_value=[]):
                result = discover_coverage(snapshot(source("/a")), config_root=self.root)
            self.assertTrue(result.static.limitations)
            self.assertEqual(result.targets[0].classification, "insufficient_evidence")
        self.write("jail.local", "[broken\n")
        with patch("offenders_coverage.get_jail_list", return_value=[]):
            result = discover_coverage(snapshot(source("/a")), config_root=self.root)
        self.assertEqual(result.targets[0].classification, "insufficient_evidence")
        self.assertTrue(any("jail.local" in error for error in result.static.limitations))
        with patch("offenders_coverage.get_jail_list", return_value=["custom-running"]), \
                patch("offenders_coverage.get_jail_sources", return_value=JailSources(
                    "custom-running", ("/a",), None, (), {"journalmatch": Fail2BanParseError("bad")})):
            covered = discover_coverage(snapshot(source("/a")), config_root=self.root)
        self.assertEqual(covered.targets[0].classification, "covered_enabled")
        self.assertTrue(covered.targets[0].limitations)
        with patch("offenders_coverage.os.open", side_effect=PermissionError("denied")):
            result = discover_static(self.root)
        self.assertTrue(any("denied" in error for error in result.limitations))

    def test_symlinks_are_confined_and_configured_identity_is_retained(self):
        self.write("target", "[custom]\nenabled=false\n")
        (self.root / "jail.conf").symlink_to(self.root / "target")
        result = discover_static(self.root)
        fragment = result.jails[0].fragments[0]
        self.assertEqual(fragment.path, str(self.root / "jail.conf"))
        self.assertEqual(fragment.resolved_path, str(self.root / "target"))
        with tempfile.TemporaryDirectory() as external:
            outside = Path(external) / "secret"
            outside.write_text("do not read")
            (self.root / "jail.local").symlink_to(outside)
            with patch("offenders_coverage.os.open", wraps=__import__("os").open) as opened:
                result = discover_static(self.root)
            self.assertNotIn(outside, [entry.args[0] for entry in opened.call_args_list])
            self.assertTrue(any("escapes" in error for error in result.limitations))

    def test_end_to_end_source_family_precedence_and_snapshot_identity(self):
        self.write("jail.conf", "[DEFAULT]\nenabled=false\nfilter=%(__name__)s\n"
                   "[sshd]\nlogpath=%(auth_log)s\n[selinux-ssh]\nlogpath=/audit\n"
                   "[local-file]\nlogpath=/var/log/site/*.log\n"
                   "[local-journal]\n[not-running]\nenabled=true\nlogpath=/configured\n")
        for name in ("sshd", "selinux-ssh", "local-file", "not-running"):
            self.write(f"filter.d/{name}.conf", "[Definition]\n")
        self.write("filter.d/local-journal.local", "[Definition]\njournalmatch=_SYSTEMD_UNIT=custom.service\n")
        shared = replace(source("/alias"), resolved_path="/var/log/auth.log", associations=(
            SourceAssociation("ssh", "installed_inactive", "first"),
            SourceAssociation("vsftpd", "listening_non_loopback", "second")))
        supplied = snapshot(shared, source("/other"), source("/var/log/site/access.log", "nginx"),
                            source("custom.service", "caddy", "journal"),
                            source("ssh.service", kind="journal"), source("/configured", "nginx"),
                            source("/no-match", "vsftpd"))
        outputs = ["Status\n|- Number of jail: 2\n`- Jail list: surprising-name, ssh",
                   "No file is currently monitored", "No journal match filter set",
                   "Current monitored log file(s):\n`- /var/log/./auth.log",
                   "Current match filter:\n_SYSTEMD_UNIT=ssh.service"]
        with patch("offenders_fail2ban.run_host_command", side_effect=[CommandResult(0, text, "") for text in outputs]) as run, \
                patch("offenders_host.discover_host_inventory", side_effect=AssertionError("rediscovery")), \
                patch("offenders_sources.discover_log_sources", side_effect=AssertionError("rediscovery")):
            result = discover_coverage(supplied, config_root=self.root)
        self.assertEqual(run.call_args_list[0], call(["fail2ban-client", "status"], timeout=8, sudo=True))
        self.assertEqual(run.call_count, 5)
        self.assertIs(result.source_inventory, supplied)
        by_identity = {(row.source.identity, row.association.family): row for row in result.targets}
        for family in ("ssh", "vsftpd"):
            self.assertEqual(by_identity["/alias", family].running_jails, ("surprising-name",))
            self.assertEqual(by_identity["/alias", family].classification, "covered_enabled")
        family_only = by_identity["/other", "ssh"]
        self.assertEqual(family_only.classification, "available_disabled")
        self.assertTrue(family_only.disabled_definitions[0].limitations)
        self.assertNotIn("selinux-ssh", [row.name for row in family_only.disabled_definitions])
        self.assertEqual(by_identity["/var/log/site/access.log", "nginx"].classification, "available_disabled")
        self.assertEqual(by_identity["custom.service", "caddy"].classification, "available_disabled")
        self.assertEqual(by_identity["ssh.service", "ssh"].classification, "covered_enabled")
        self.assertEqual(by_identity["/configured", "nginx"].classification, "insufficient_evidence")
        self.assertEqual(result.unassociated_listeners[0].observation, supplied.unassociated_listeners[0])
        # This snapshot's caddy source means its caddy service is represented.
        self.assertFalse(result.services_without_sources)

    def test_complete_negatives_partial_runtime_and_unresolved_definitions(self):
        supplied = snapshot(source("/a"), source("ssh.service", kind="journal"),
                            LogSource("file", "/generic", "unavailable"))
        with patch("offenders_coverage.get_jail_list", return_value=[]):
            result = discover_coverage(supplied, config_root=self.root)
        self.assertEqual([row.classification for row in result.targets],
                         ["no_obvious_match", "insufficient_evidence", "no_obvious_match"])
        self.assertEqual(result.services_without_sources[0].classification, "insufficient_evidence")
        error = Fail2BanParseError("bad status")
        with patch("offenders_coverage.get_jail_list", side_effect=error):
            result = discover_coverage(supplied, config_root=self.root)
        self.assertIs(result.runtime_error, error)
        self.assertTrue(all(row.classification == "insufficient_evidence" for row in result.targets))
        running = JailSources("ssh", (), None, (), {"journalmatch": error})
        with patch("offenders_coverage.get_jail_list", return_value=["ssh"]), \
                patch("offenders_coverage.get_jail_sources", return_value=running):
            result = discover_coverage(supplied, config_root=self.root)
        self.assertEqual(result.targets[0].classification, "no_obvious_match")
        self.assertEqual(result.targets[-1].classification, "insufficient_evidence")
        for config in ("[sshd]\nenabled=false\nfilter=missing\n", "[sshd]\nenabled=true\nfilter=sshd\n",
                       "[sshd]\nenabled=maybe\nfilter=sshd\n", "[custom]\nenabled=false\nfilter=%(unknown)s\n"):
            self.write("jail.conf", config)
            self.write("filter.d/sshd.conf", "[Definition]\n")
            with self.subTest(config=config), patch("offenders_coverage.get_jail_list", return_value=[]):
                result = discover_coverage(supplied, config_root=self.root)
            self.assertEqual(result.targets[0].classification, "insufficient_evidence")

    def test_includes_preserve_family_candidates_but_not_complete_negatives(self):
        self.write("jail.conf", "[INCLUDES]\nbefore=paths-common.conf\n"
                   "[DEFAULT]\nenabled=false\nfilter=%(__name__)s\n"
                   "[sshd]\nlogpath=%(auth_log)s\n")
        self.write("filter.d/sshd.conf", "[INCLUDES]\nbefore=common.conf\n[Definition]\n")
        with patch("offenders_coverage.get_jail_list", return_value=[]):
            result = discover_coverage(snapshot(source("/auth"), source("/ftp", "vsftpd")),
                                       config_root=self.root)
        self.assertEqual(result.targets[0].classification, "available_disabled")
        self.assertEqual(result.targets[1].classification, "insufficient_evidence")
        self.assertTrue(result.static.limitations)

    def test_literal_matches_never_expand_or_invent_units_and_order_is_stable(self):
        self.write("jail.conf", "[custom]\nenabled=false\nfilter=custom\nlogpath=/site/*.log\n")
        self.write("filter.d/custom.local", "[Definition]\njournalmatch=_SYSTEMD_UNIT=other.service\n")
        supplied = snapshot(source("/site/access.log"), source("/site/nested/access.log"),
                            source("ssh.service", kind="journal"))
        runtime = JailSources("sshd", (), "SYSLOG_IDENTIFIER=sshd", ())
        with patch("offenders_coverage.get_jail_list", return_value=["sshd"]), \
                patch("offenders_coverage.get_jail_sources", return_value=runtime):
            first = discover_coverage(supplied, config_root=self.root)
            second = discover_coverage(replace(supplied, sources=tuple(reversed(supplied.sources))),
                                       config_root=self.root)
        self.assertEqual(first.targets, second.targets)
        self.assertEqual([row.classification for row in first.targets],
                         ["available_disabled", "no_obvious_match", "insufficient_evidence"])
        self.write("filter.d/custom.local", "[Definition]\njournalmatch=_SYSTEMD_UNIT=other.service %(unknown)s\n")
        with patch("offenders_coverage.get_jail_list", return_value=[]):
            result = discover_coverage(snapshot(source("ssh.service", kind="journal")), config_root=self.root)
        self.assertEqual(result.targets[0].classification, "insufficient_evidence")
