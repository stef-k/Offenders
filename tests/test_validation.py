"""Offline validation contracts using retained snapshots and an inspecting runner."""
from dataclasses import replace
import hashlib
from pathlib import Path
import stat
import unittest
from unittest.mock import patch

from offenders_evidence import EvidenceRecord
from offenders_fail2ban import CommandFailure, CommandResult
from offenders_findings import build_findings
import offenders_validation as validation
from test_findings import fixture


def inventory(*, custom=False, texts=('one', 'two', 'three'), context=('background',), **options):
    """Attach retained logical records to the existing public finding fixture."""
    if not custom and not options:
        options = {'disabled': (('renamed', 'sshd'),)}
    patterns, coverage = fixture(**options)
    records = tuple(EvidenceRecord(('file', i), True, (('file', '/alias'),), text)
                    for i, text in enumerate((*texts, *context)))
    group = replace(patterns.groups[0], record_ids=tuple(row.identity for row in records[:len(texts)]))
    patterns = replace(patterns, groups=(group,), evidence_snapshot=replace(patterns.evidence_snapshot, records=records))
    return build_findings(patterns, coverage)


class ValidationTests(unittest.TestCase):
    """Prove identity, two-pass command/file boundaries, and conservative results."""

    def run_existing(self, inv, runner=None):
        """Run the public API with a deterministic summary-producing command seam."""
        decision = inv.findings[0]
        with patch.object(validation, 'run_host_command', side_effect=runner,
                          return_value=CommandResult(0, 'Lines: 3 lines, 1 ignored, 1 matched, 1 missed', '')) as run:
            result = validation.validate_existing(inv, decision, validation.eligible_targets(inv, decision)[0])
        return result, run

    def test_exact_objects_and_candidate_classes(self):
        inv = inventory()
        decision = inv.findings[0]
        target = decision.disabled_candidates[0]
        with patch.object(validation, 'run_host_command') as run:
            for selected, match in ((replace(decision), target), (decision, replace(target)),
                                    (replace(decision, classification='insufficient_evidence'), target)):
                result = validation.validate_existing(inv, selected, match)
                self.assertEqual(result.state, 'unavailable')
            result = validation.validate_custom(inv, decision, '[Definition]\nfailregex = x')
            self.assertEqual(result.state, 'unavailable')
            run.assert_not_called()
        enabled = inventory(running=(('live', 'sshd'),), count=20)
        result, run = self.run_existing(enabled)
        self.assertEqual(result.jail_name, 'live')
        self.assertEqual(run.call_count, 2)

    def test_two_pass_membership_files_and_exact_command(self):
        inv = inventory(texts=('one\nembedded', 'two\n', 'three'))
        patterns = inv.pattern_inventory
        records = (*patterns.evidence_snapshot.records,
                   EvidenceRecord(('file', 9), True, (('file', '/other'),), 'unrelated'))
        inv = replace(inv, pattern_inventory=replace(patterns,
            evidence_snapshot=replace(patterns.evidence_snapshot, records=records)))
        files, content = [], []

        def run(args, **kwargs):
            self.assertEqual(kwargs, {'timeout': 8, 'sudo': False})
            self.assertEqual(args[:8], ['fail2ban-regex', '--usedns=no', '--encoding=utf-8',
                '--print-no-missed', '--print-no-ignored', '-c', '/etc/fail2ban', '--'])
            self.assertEqual(args[-1], 'sshd')
            path = Path(args[-2])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            files.append(path)
            content.append(path.read_bytes())
            return CommandResult(0, 'Lines: 4 lines, 1 ignored, 2 matched, 1 missed', '')

        result, _ = self.run_existing(inv, run)
        self.assertEqual(content, [b'one\nembedded\ntwo\nthree\n', b'background\n'])
        self.assertEqual(result.target.selected_records, 3)
        self.assertEqual(result.target.tested_lines, 4)
        self.assertEqual(result.state, 'partial')
        self.assertTrue(all(not path.parent.exists() for path in files))
        self.assertIs(result.decision, inv.findings[0])

    def test_alias_context_and_missing_target(self):
        inv = inventory()
        patterns = inv.pattern_inventory
        analysis = replace(patterns.analyses[0], source_keys=(('file', '/alias'), ('file', '/alias2')))
        records = (*patterns.evidence_snapshot.records,
                   EvidenceRecord(('file', 9), True, (('file', '/alias2'),), 'background'))
        inv = replace(inv, pattern_inventory=replace(patterns, analyses=(analysis,),
            evidence_snapshot=replace(patterns.evidence_snapshot, records=records)))
        result, _ = self.run_existing(inv)
        self.assertEqual(result.context.available_records, 2)  # Equal content is not deduplicated.
        missing = replace(inv, pattern_inventory=replace(inv.pattern_inventory,
            evidence_snapshot=replace(patterns.evidence_snapshot, records=records[1:])))
        result, run = self.run_existing(missing)
        self.assertEqual(result.state, 'unavailable')
        run.assert_not_called()

    def test_safe_options_or_explicit_base_fallback(self):
        inv = inventory(disabled=(('sshd', 'sshd'),))
        for raw, expected, reproduced in (
            ('sshd[mode=aggressive]', 'sshd[mode=aggressive]', True),
            ('%(__name__)s[mode="normal"]', 'sshd[mode="normal"]', True),
            ('sshd[mode=%(mode)s]', 'sshd', False),
            ('sshd\n[mode=normal]', 'sshd', False),
            ('other[mode=normal]', 'sshd', False),
        ):
            static = inv.coverage_inventory.static
            changed = replace(inv, coverage_inventory=replace(inv.coverage_inventory,
                static=replace(static, jails=(replace(static.jails[0], filter_raw=raw),))))
            result, run = self.run_existing(changed)
            self.assertEqual(result.filter_argument, expected)
            self.assertEqual(result.effective_options_reproduced, reproduced)
            self.assertEqual(run.call_args.args[0][-1], expected)
            if not reproduced:
                self.assertIn(validation.OPTIONS_FALLBACK, result.limitations)

    def test_bounds_omissions_absent_context_and_empty_target(self):
        for texts, count in ((tuple(str(i) for i in range(45)), 40),
                             (('é' * 20000,) * 3, 1), (('bad\0text', 'ok'), 1)):
            result, _ = self.run_existing(inventory(texts=texts, context=()))
            self.assertEqual(result.target.available_records, len(texts))
            self.assertEqual(result.target.selected_records, count)
            self.assertTrue(result.target.truncated)
            self.assertLessEqual(result.target.written_bytes, 65536)
            self.assertLessEqual(len(result.target.examples), 3)
            self.assertTrue(all(len(text.encode()) <= 512 for text in result.target.examples))
            self.assertIsNone(result.context)
            self.assertEqual(result.state, 'partial')
        result, run = self.run_existing(inventory(texts=('\0',)))
        self.assertEqual(result.state, 'unavailable')
        run.assert_not_called()

    def test_parser_and_command_failures_cleanup_and_retention(self):
        good = 'Lines: 3 lines, 0 ignored, 0 matched, 3 missed'
        cases = [(CommandResult(0, good, ''), None),
                 *[(CommandResult(0, text, ''), 'summary') for text in
                   ('', good + '\n' + good, 'Lines: -1 lines, 0 ignored, 0 matched, 0 missed',
                    'Lines: 3 lines, 0 ignored, 1 matched, 3 missed')],
                 *[(CommandResult(None, good, 'é' * 500, failure), failure)
                   for failure in CommandFailure]]
        for command, expected in cases:
            paths = []

            def run(args, **kwargs):
                paths.append(Path(args[-2]))
                return command

            result, _ = self.run_existing(inventory(), run)
            self.assertTrue(all(not path.parent.exists() for path in paths))
            self.assertLessEqual(len(result.target.detail.encode()), 300)
            if expected is None:
                self.assertEqual(result.target.matched_lines, 0)
            else:
                self.assertEqual(result.state, 'unavailable')
                self.assertIsNone(result.target.matched_lines)
        with patch.object(validation, 'run_host_command', side_effect=[
            CommandResult(0, good, ''), CommandResult(None, '', '', CommandFailure.TIMEOUT)]):
            inv = inventory()
            result = validation.validate_existing(inv, inv.findings[0], inv.findings[0].disabled_candidates[0])
        self.assertEqual(result.state, 'partial')
        self.assertEqual(result.target.matched_lines, 0)
        self.assertEqual(result.context.failure, CommandFailure.TIMEOUT)

    def test_custom_preflight_fingerprint_and_private_cleanup(self):
        inv = inventory(custom=True)
        decision = inv.findings[0]
        invalid = ('/etc/filter.conf', '[Definition]\nfailregex=', '[Definition]\nfailregex=x\0',
                   '[INCLUDES]\nbefore=x\n[Definition]\nfailregex=x', '[Other]\nx=y',
                   '[Definition]\nfailregex=' + 'x' * 65536, '[Definition]\nfailregex=\ud800')
        with patch.object(validation, 'run_host_command') as run:
            for text in invalid:
                self.assertEqual(validation.validate_custom(inv, decision, text).state, 'unavailable')
            run.assert_not_called()
        text = '[Definition]\nfailregex = ^failed <HOST>$\n[Init]\nmode = normal\n'
        paths = []

        def run(args, **kwargs):
            path = Path(args[-1])
            paths.append(path)
            self.assertEqual(path.suffix, '.conf')
            self.assertEqual(path.read_bytes(), text.encode())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            return CommandResult(0, 'Lines: 1 lines, 0 ignored, 1 matched, 0 missed', '')

        with patch.object(validation, 'run_host_command', side_effect=run):
            result = validation.validate_custom(inv, decision, text)
        self.assertEqual(result.custom_sha256, hashlib.sha256(text.encode()).hexdigest())
        self.assertEqual(result.custom_bytes, len(text.encode()))
        self.assertTrue(all(not path.exists() for path in paths))

    def test_stdout_tail_and_custom_failure_cleanup(self):
        summary = 'Lines: 3 lines, 0 ignored, 0 matched, 3 missed'
        for output, usable in ((summary + '\n' + 'x' * validation.OUTPUT_BYTES, False),
                               ('x' * validation.OUTPUT_BYTES + '\n' + summary, True)):
            result, _ = self.run_existing(inventory(), lambda *args, **kwargs: CommandResult(0, output, ''))
            self.assertEqual(result.target.tested_lines is not None, usable)
        inv = inventory(custom=True)
        text = '[Definition]\nfailregex = ^failed <HOST>$'
        for command in (CommandResult(0, 'malformed', ''),
                        CommandResult(None, '', '', CommandFailure.TIMEOUT)):
            paths = []

            def run(args, **kwargs):
                paths.extend((Path(args[-2]), Path(args[-1])))
                return command

            with patch.object(validation, 'run_host_command', side_effect=run):
                result = validation.validate_custom(inv, inv.findings[0], text)
            self.assertEqual(result.state, 'unavailable')
            self.assertEqual(result.custom_sha256, hashlib.sha256(text.encode()).hexdigest())
            self.assertTrue(all(not path.parent.exists() for path in paths))

    def test_complete_requires_unlimited_target_and_context(self):
        inv = inventory()
        result, _ = self.run_existing(inv)
        self.assertEqual(result.state, 'complete')
        self.assertTrue(result.limitations)  # Interpretation caveats remain visible.
        patterns = inv.pattern_inventory
        limited = replace(inv, pattern_inventory=replace(patterns,
            evidence_snapshot=replace(patterns.evidence_snapshot, truncated=True)))
        self.assertEqual(self.run_existing(limited)[0].state, 'partial')
