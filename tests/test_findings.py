"""Same-snapshot public policy fixtures; no host or Fail2Ban acquisition."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch

from offenders_coverage import CoverageInventory, CoverageTarget, DefinitionMatch, JailDefinition, StaticInventory
from offenders_evidence import EvidenceRecord, EvidenceSnapshot, SourceResult
from offenders_findings import build_findings
from offenders_host import HostInventory, SourceHealth
from offenders_patterns import COUNT_NOTE, PatternGroup, PatternInventory, SourceFamilyAnalysis, analyze_patterns
from offenders_sources import LogSource, LogSourceInventory, SourceAssociation


def fixture(*, count=3, global_ips=1, family="ssh", kind="ssh_failed_password",
            signature="ssh_failed_password", state="listening_non_loopback", running=(), disabled=(),
            classification="no_obvious_match", analysis="analyzed", backend="file"):
    """Supply bounded upstream facts with independently named jail/filter pairs."""
    source = LogSource(backend, "/alias" if backend == "file" else "ssh.service", "readable",
                       (SourceAssociation(family, state, "fixture"),), "/real" if backend == "file" else None)
    host = HostInventory((), (), *(SourceHealth("successful"),) * 3)
    sources = LogSourceInventory(host, (source,), ())
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    evidence = EvidenceSnapshot(sources, now, timedelta(days=1), now - timedelta(days=1), (), (), False, ())
    identity = source.resolved_path or source.identity
    group = PatternGroup(family, backend, identity, kind, signature, "utc", count,
                         max(1, global_ips), global_ips, int(global_ips == 0), now, now,
                         (), ("observed record",), (COUNT_NOTE,))
    patterns = PatternInventory(evidence, (), (group,), (SourceFamilyAnalysis(
        backend, identity, family, ((backend, source.identity),), analysis, count, count, 0, 0, ()),))
    jails = tuple(JailDefinition(name, bool((name, stem) in running), stem or "", stem, "", (), "", (), ())
                  for name, stem in (*running, *disabled))
    target = CoverageTarget(source, source.associations[0], classification,
                            tuple(name for name, _ in running),
                            tuple(DefinitionMatch(name, "literal configured file pattern") for name, _ in disabled), ())
    coverage = CoverageInventory(sources, (), None, StaticInventory(jails, (), (), ()), (target,), (), ())
    return patterns, coverage


class FindingTests(unittest.TestCase):
    """Exercise candidate precedence and evidence boundaries at the public join."""

    def test_thresholds_and_service_states(self):
        cases = [({"count": 1}, "below_recurrence_threshold"),
                 ({"count": 2}, "below_recurrence_threshold"),
                 ({"global_ips": 0}, "non_global_only"),
                 ({"state": "installed_inactive"}, "inactive_service"),
                 ({"state": "future_state"}, "insufficient_evidence"),
                 ({"state": ""}, "insufficient_evidence"),
                 ({}, "custom_gap_candidate")]
        for options, expected in cases:
            with self.subTest(options=options):
                result = build_findings(*fixture(**options))
                self.assertEqual(result.decisions[0].classification, expected)
                self.assertIn(COUNT_NOTE, result.decisions[0].limitations)
        for state, note in (("listening_loopback", "loopback"),
                            ("active_listener_unknown", "ownership"),
                            ("active_no_matching_listener_observed", None)):
            result = build_findings(*fixture(state=state))
            self.assertEqual(len(result.findings), 1)
            if note:
                self.assertIn(note, " ".join(result.findings[0].limitations))

    def test_snapshot_identity_alias_union_and_missing_coverage(self):
        patterns, coverage = fixture(disabled=(("custom-name", "sshd"),), classification="available_disabled")
        result = build_findings(patterns, coverage)
        self.assertIs(result.pattern_inventory, patterns)
        self.assertIs(result.coverage_inventory, coverage)
        self.assertIs(result.findings[0].group, patterns.groups[0])
        with self.assertRaisesRegex(ValueError, "exact same"):
            build_findings(patterns, replace(coverage, source_inventory=replace(coverage.source_inventory)))
        weak = replace(coverage.targets[0], source=replace(coverage.targets[0].source, identity="/real"),
                       classification="insufficient_evidence", disabled_definitions=(), limitations=("alias unavailable",))
        joined = build_findings(patterns, replace(coverage, targets=(weak, *coverage.targets, coverage.targets[0])))
        self.assertEqual(len(joined.findings), 1)
        self.assertEqual(len(joined.findings[0].disabled_candidates), 1)
        self.assertEqual(joined.findings[0].group.event_count, 3)
        self.assertIn("alias unavailable", joined.findings[0].limitations)
        self.assertEqual(len(joined.findings[0].coverage_targets), 3)
        self.assertEqual(build_findings(patterns, replace(coverage, targets=())).decisions[0].classification,
                         "insufficient_evidence")
        self.assertEqual(len(build_findings(*fixture(backend="journal")).findings), 1)

    def test_enabled_thresholds_and_unknown_relevance_precedence(self):
        for count, ips, expected in ((3, 1, False), (9, 2, False), (10, 2, True),
                                     (19, 1, False), (20, 1, True)):
            with self.subTest(count=count, ips=ips):
                result = build_findings(*fixture(count=count, global_ips=ips,
                    running=(("unusual-name", "sshd"), ("other", "custom")), disabled=(("spare", "sshd"),)))
                self.assertEqual(result.decisions[0].classification,
                    "enabled_tuning_question" if expected else "enabled_relevant_below_tuning_threshold")
                self.assertEqual(result.decisions[0].running_filters[0].name, "unusual-name")
        for stem in ("custom", None):
            result = build_findings(*fixture(running=(("sshd", stem),), disabled=(("spare", "sshd"),)))
            self.assertEqual(result.decisions[0].classification, "insufficient_evidence")
        patterns, coverage = fixture(running=(("renamed", "sshd"),))
        coverage = replace(coverage, static=replace(coverage.static, jail_reads_complete=False))
        self.assertEqual(build_findings(patterns, coverage).decisions[0].classification, "insufficient_evidence")
        other = build_findings(*fixture(running=(("web", "apache-auth"),), disabled=(("ssh-off", "sshd"),)))
        self.assertEqual(other.findings[0].classification, "existing_disabled_candidate")

    def test_exact_stock_pattern_narrowing(self):
        for family in ("nginx", "apache"):
            auth = f"{family}-http-auth" if family == "nginx" else "apache-auth"
            cases = [(f"{family}_http_authentication_failure", "auth", auth, True),
                     (f"{family}_http_authentication_failure", "auth", f"{family}-botsearch", False)]
            cases += [("path_probe", f"{family}:path_probe:{category}", f"{family}-botsearch", compatible)
                      for category, compatible in (("database_admin", True), ("cgi_script", True),
                          ("wordpress_auth", False), ("sensitive_dotfile", False), ("path_traversal", False))]
            for kind, signature, stem, compatible in cases:
                with self.subTest(family=family, signature=signature, stem=stem):
                    options = dict(family=family, kind=kind, signature=signature)
                    result = build_findings(*fixture(**options, running=(("arbitrary", stem),)))
                    self.assertEqual(result.decisions[0].classification,
                        "enabled_relevant_below_tuning_threshold" if compatible else "insufficient_evidence")
                    result = build_findings(*fixture(**options, disabled=(("arbitrary", stem),),
                                                     classification="available_disabled"))
                    partial = signature.endswith(":wordpress_auth")
                    self.assertEqual(bool(result.findings), compatible or partial)
                    if partial:
                        self.assertIn("partial/ambiguous", " ".join(result.findings[0].limitations))
        for family, kind, stem in (("ssh", "ssh_invalid_user", "sshd"),
            ("ssh", "ssh_authentication_failure", "sshd"),
            ("dovecot", "dovecot_authentication_failure", "dovecot"),
            ("vsftpd", "vsftpd_login_failure", "vsftpd"),
            ("proftpd", "proftpd_login_failure", "proftpd"),
            ("proftpd", "proftpd_root_login", "proftpd"),
            ("pure-ftpd", "pure-ftpd_authentication_failure", "pure-ftpd")):
            result = build_findings(*fixture(family=family, kind=kind, disabled=(("renamed", stem),)))
            self.assertEqual(result.findings[0].classification, "existing_disabled_candidate")

    def test_custom_disabled_and_incomplete_evidence(self):
        patterns, coverage = fixture(disabled=(("ssh-lookalike", "custom"),), classification="available_disabled")
        for reason, candidate in (("literal configured file pattern", True), ("exact filter journal unit", True),
                                   ("exact stock family catalog", False)):
            target = replace(coverage.targets[0], disabled_definitions=(DefinitionMatch("ssh-lookalike", reason),))
            result = build_findings(patterns, replace(coverage, targets=(target,)))
            self.assertEqual(bool(result.findings), candidate)
            if candidate:
                self.assertIn("unvalidated", " ".join(result.findings[0].limitations))
        for analysis in ("unsupported", "unavailable", "skipped"):
            self.assertFalse(build_findings(*fixture(analysis=analysis)).findings)
        for classification in ("insufficient_evidence", "available_disabled", "covered_enabled"):
            self.assertFalse(build_findings(*fixture(classification=classification)).findings)
        patterns, coverage = fixture(analysis="partial")
        patterns = replace(patterns, evidence_snapshot=replace(patterns.evidence_snapshot,
            truncated=True, limitations=("history partial",)), groups=(replace(patterns.groups[0], timestamp_basis="local_wall"),))
        result = build_findings(patterns, coverage)
        self.assertEqual(len(result.findings), 1)
        self.assertIn("history partial", result.findings[0].limitations)
        self.assertIn("evidence/history was truncated", result.findings[0].limitations)
        self.assertIn("UTC lookback", " ".join(result.findings[0].limitations))

    def test_recognized_records_flow_through_canonical_join(self):
        patterns, coverage = fixture(disabled=(("ssh-review", "sshd"),))
        source = coverage.source_inventory.sources[0]
        records = tuple(EvidenceRecord(("file", index), True, (("file", source.identity),),
            f"Failed password for user{index} from 8.8.8.8 port 22") for index in range(3))
        evidence = replace(patterns.evidence_snapshot, records=records, sources=(SourceResult(
            source, "collected", tuple(row.identity for row in records), False, ()),))
        recognized = analyze_patterns(evidence)
        result = build_findings(recognized, coverage)
        self.assertEqual(result.findings[0].classification, "existing_disabled_candidate")
        self.assertEqual(result.findings[0].group.source_identity, "/real")
        self.assertEqual(result.findings[0].group.event_count, 3)
        self.assertEqual(result.findings[0].group.global_source_ip_count, 1)
        self.assertIs(result.findings[0].group, recognized.groups[0])
        missing = replace(coverage.source_inventory, sources=(replace(source, associations=()),))
        self.assertEqual(build_findings(replace(recognized, evidence_snapshot=replace(evidence,
            source_inventory=missing)), replace(coverage, source_inventory=missing)).decisions[0].classification,
            "insufficient_evidence")
        unresolved = replace(coverage, static=replace(coverage.static,
            jails=(replace(coverage.static.jails[0], filter_stem=None),)))
        self.assertFalse(build_findings(recognized, unresolved).findings)

    def test_order_bounds_and_no_io(self):
        patterns, coverage = fixture(disabled=(("z", "sshd"), ("a", "sshd")))
        groups = (replace(patterns.groups[0], signature="z"), replace(patterns.groups[0], signature="a", event_count=1))
        patterns = replace(patterns, groups=groups)
        with patch("builtins.open", side_effect=AssertionError("filesystem I/O")), \
             patch("subprocess.run", side_effect=AssertionError("command I/O")), \
             patch("socket.socket", side_effect=AssertionError("network I/O")):
            result = build_findings(patterns, coverage)
            reversed_result = build_findings(replace(patterns, groups=tuple(reversed(groups)),
                analyses=tuple(reversed(patterns.analyses))), replace(coverage,
                targets=tuple(reversed(coverage.targets)), static=replace(coverage.static,
                    jails=tuple(reversed(coverage.static.jails)))))
        self.assertEqual(result.decisions, reversed_result.decisions)
        self.assertEqual(len(result.decisions), 2)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual([row.name for row in result.findings[0].disabled_candidates], ["a", "z"])
        large = replace(patterns, groups=(replace(groups[0], limitations=tuple(f"{i}:" + "é" * 400 for i in range(40))),))
        decision = build_findings(large, coverage).decisions[0]
        self.assertLessEqual(len(decision.limitations), 32)
        self.assertTrue(all(len(note.encode("utf-8")) <= 300 for note in decision.limitations))
        self.assertLessEqual(len(decision.group.examples), 3)
        self.assertFalse(any("score" in name or "severity" in name for name in decision.__dataclass_fields__))
