"""Offline presentation and causal worker lifecycle checks for manual coverage."""
import asyncio
from contextlib import ExitStack
from dataclasses import replace
import threading
import unittest
from unittest.mock import patch

from textual.widgets import DataTable, Static

from offenders import OffendersApp
from offenders_findings import build_findings
import offenders_recommendations_ui as ui
from test_findings import fixture
from test_refresh import report


class PresentationTests(unittest.TestCase):
    """Verify existing policy objects are presented without additional acquisition."""

    def test_workflow_order_and_exact_identity(self):
        patterns, coverage = fixture()
        expected = build_findings(patterns, coverage)
        sources = coverage.source_inventory
        steps = [
            ('discover_host_inventory', (), sources.host_inventory),
            ('discover_log_sources', (sources.host_inventory,), sources),
            ('discover_coverage', (sources,), coverage),
            ('EvidenceCollector.collect', (sources,), patterns.evidence_snapshot),
            ('analyze_patterns', (patterns.evidence_snapshot,), patterns),
            ('build_findings', (patterns, coverage), expected),
        ]
        calls = []
        with ExitStack() as stack:
            for name, arguments, result in steps:
                def invoke(*args, name=name, arguments=arguments, result=result):
                    self.assertEqual(len(args), len(arguments))
                    for actual, wanted in zip(args, arguments):
                        self.assertIs(actual, wanted)
                    calls.append(name)
                    return result
                stack.enter_context(patch(f'offenders_recommendations_ui.{name}', side_effect=invoke))
            self.assertIs(ui.run_analysis(), expected)
        self.assertEqual(calls, [step[0] for step in steps])

    def test_candidate_details_and_time_domains(self):
        cases = [({'disabled': (('spare', 'sshd'),)}, 'Filter suitability is not yet established'),
                 ({'running': (('live', 'sshd'),), 'count': 20}, 'does not prove the jail failed'),
                 ({}, 'No custom configuration has been generated')]
        for options, caveat in cases:
            decision = build_findings(*fixture(**options)).findings[0]
            group = replace(decision.group, examples=('[bold]literal[/bold]', 'two', 'three'))
            decision = replace(decision, group=group, limitations=('first limit', 'second limit'))
            text = ui.finding_detail(decision)
            for value in (ui.REVIEW_LABELS[decision.classification], decision.reason, caveat,
                          'listening_non_loopback', '/real', 'ssh_failed_password',
                          'Distinct source IPs: 1', 'Global source IPs: 1', 'Non-global source IPs: 0',
                          '2026-01-01T00:00:00Z', '[bold]literal[/bold]\ntwo\nthree',
                          'first limit\nsecond limit', 'no_obvious_match'):
                self.assertIn(value, text)
            for match in (*decision.running_filters, *decision.disabled_candidates):
                self.assertIn(f'{match.name} / filter {match.filter_stem}', text)
            local = replace(group, timestamp_basis='local_wall', first_seen=group.first_seen.replace(tzinfo=None))
            text = ui.finding_detail(replace(decision, group=local))
            self.assertIn('local wall clock', text)
            self.assertIn('exact UTC lookback could not be enforced', text)
            self.assertNotIn('00:00:00Z', text)
        self.assertEqual(ui.format_time(None, 'unknown'), 'unknown')
        self.assertEqual(ui.format_time(None, 'utc'), 'unavailable')

    def test_normal_empty_results_and_source_completeness(self):
        inventory = build_findings(*fixture(count=1))
        decisions = tuple(replace(inventory.decisions[0], classification=key) for key in ui.SUPPRESSION_LABELS)
        text = ui.analysis_summary(replace(inventory, decisions=decisions))
        self.assertTrue(text.startswith('No recommendation'))
        for label in ui.SUPPRESSION_LABELS.values():
            self.assertIn(f'{label}: 1', text)
        patterns = inventory.pattern_inventory
        for states in (('analyzed',), ('unsupported', 'unavailable', 'partial', 'skipped')):
            analyses = tuple(replace(patterns.analyses[0], state=state) for state in states)
            empty = replace(inventory, decisions=(), pattern_inventory=replace(patterns, groups=(), analyses=analyses))
            text = ui.analysis_summary(empty)
            self.assertIn('No supported pattern was recognized', text)
            self.assertNotIn('Analysis unavailable', text)
            if 'unsupported' in states:
                self.assertIn('unsupported source families: 1', text)
                self.assertIn('unavailable/skipped/partial source analyses: 3', text)
                self.assertIn('Evidence completeness: partial', text)
            else:
                self.assertIn('Supported sources analyzed: 1', text)


class ScreenTests(unittest.IsolatedAsyncioTestCase):
    """Exercise real app routing, neutral loading, cancellation, rows and errors."""

    async def test_manual_screen_lifecycle(self):
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        result = build_findings(*fixture())
        second = replace(result.findings[0], classification='existing_disabled_candidate')
        result = replace(result, findings=(*result.findings, second))
        ui_thread = threading.get_ident()

        def pending():
            self.assertNotEqual(threading.get_ident(), ui_thread)
            entered.set()
            try:
                if not release.wait(10):
                    raise AssertionError('worker not released')
                return result
            finally:
                finished.set()

        with patch('offenders.build_report', return_value=report()), \
             patch('offenders_geoip_ui.read_state', return_value={}), \
             patch.object(ui, 'run_analysis', side_effect=pending) as run:
            app = OffendersApp()
            async with app.run_test(size=(120, 50)) as pilot:
                try:
                    await app.workers.wait_for_complete()
                    app.refresh_report()  # The timer uses this exact callback.
                    await app.workers.wait_for_complete()
                    await pilot.press('r', 'p', 'v')
                    await app.workers.wait_for_complete()
                    run.assert_not_called()
                    await pilot.press('a')
                    self.assertTrue(await asyncio.to_thread(entered.wait, 3))
                    old = app.screen
                    self.assertIn('Analyzing coverage', str(old.query_one('#coverage-summary', Static).content))
                    await pilot.press('a')
                    self.assertIs(app.screen, old)
                    self.assertEqual(run.call_count, 1)
                    await pilot.press('escape')
                    self.assertIs(app.screen, app.default_screen)
                    release.set()
                    self.assertTrue(await asyncio.to_thread(finished.wait, 3))
                    run.side_effect = None
                    run.return_value = result
                    await pilot.press('a')
                    await app.workers.wait_for_complete()
                    current = app.screen
                    self.assertIsNone(old.inventory)
                    self.assertIs(current.inventory, result)
                    table = current.query_one(DataTable)
                    self.assertEqual(table.row_count, 2)
                    self.assertIs(current.decisions['0'], result.findings[0])
                    self.assertIs(current.decisions['1'], second)
                    await pilot.press('down')
                    self.assertIn(ui.REVIEW_LABELS[second.classification], str(current.query_one('#coverage-detail', Static).content))
                    await pilot.press('q')
                    self.assertIs(app.screen, app.default_screen)
                    saved = app._last_report
                    run.side_effect = RuntimeError('\x00bad\n' + 'x' * 500)
                    await pilot.press('a')
                    await app.workers.wait_for_complete()
                    text = str(app.screen.query_one('#coverage-summary', Static).content)
                    self.assertIn('Analysis unavailable', text)
                    self.assertNotIn('No recommendation', text)
                    self.assertEqual(len(text.splitlines()[-1]), 240)
                    self.assertIs(app._last_report, saved)
                    await pilot.press('q')
                finally:
                    release.set()
