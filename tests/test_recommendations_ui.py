"""Offline presentation and causal worker lifecycle checks for manual coverage."""
import asyncio
from contextlib import ExitStack
from dataclasses import replace
from datetime import timedelta
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
                def invoke(*args, name=name, arguments=arguments, result=result, **kwargs):
                    self.assertEqual(len(args), len(arguments))
                    for actual, wanted in zip(args, arguments):
                        self.assertIs(actual, wanted)
                    self.assertEqual(kwargs, {'lookback': lookback} if name == 'EvidenceCollector.collect' else {})
                    calls.append(name)
                    return result
                stack.enter_context(patch(f'offenders_recommendations_ui.{name}', side_effect=invoke))
            for lookback in (timedelta(days=7), timedelta(hours=24)):
                self.assertIs(ui.run_analysis(lookback), expected)
        self.assertEqual(calls, [step[0] for step in steps] * 2)

    def test_suppressed_detail_preserves_reason_and_evidence(self):
        """Below-threshold and unavailable decisions explain facts without recommending."""
        for options in ({'count': 1}, {'analysis': 'unavailable'}):
            decision = build_findings(*fixture(**options)).decisions[0]
            text = ui.finding_detail(decision)
            for value in ('Suppressed / not a recommendation',
                          ui.SUPPRESSION_LABELS[decision.classification], decision.reason,
                          'Service family: ssh', 'listening_non_loopback', 'Source kind: file',
                          'Canonical source: /real', 'ssh_failed_password',
                          f'Recognized records: {decision.group.event_count}',
                          'Distinct source IPs: 1', 'Global source IPs: 1', 'Non-global source IPs: 0',
                          '2026-01-01T00:00:00Z', 'Timestamp basis: utc',
                          'no_obvious_match', *decision.group.examples, *decision.limitations):
                self.assertIn(value, text)

    def test_early_suppression_reports_relevance_as_not_evaluated(self):
        """Source monitoring survives early gates without claiming filter relevance."""
        cases = ({'count': 1}, {'global_ips': 0}, {'state': 'installed_inactive'},
                 {'analysis': 'unavailable'})
        for options in cases:
            with self.subTest(options=options):
                inventory = build_findings(*fixture(**options, classification='covered_enabled',
                    running=(('live', 'sshd'),), disabled=(('spare', 'sshd'),)))
                decision = inventory.decisions[0]
                self.assertFalse(inventory.findings)
                self.assertFalse(decision.running_filters)
                self.assertFalse(decision.disabled_candidates)
                text = ui.finding_detail(decision)
                self.assertIn('Coverage classifications: covered_enabled', text)
                for label in ('Relevant running jail', 'Retained disabled jail'):
                    self.assertIn(f'{label}: not evaluated for this suppressed decision', text)
                    self.assertNotIn(f'{label}: none established', text)

    def test_policy_evaluated_details_keep_concrete_relevance_and_empty_results(self):
        """Evaluated candidates, enabled suppression and unknown relevance retain semantics."""
        cases = (({'disabled': (('spare', 'sshd'),)}, 'existing_disabled_candidate',
                  'none established', 'spare / filter sshd'),
                 ({'running': (('live', 'sshd'),), 'count': 20}, 'enabled_tuning_question',
                  'live / filter sshd', 'none established'),
                 ({'running': (('live', 'sshd'),)}, 'enabled_relevant_below_tuning_threshold',
                  'live / filter sshd', 'none established'),
                 ({'running': (('live', None),)}, 'insufficient_evidence',
                  'none established', 'none established'))
        for options, classification, running, disabled in cases:
            with self.subTest(classification=classification):
                decision = build_findings(*fixture(**options)).decisions[0]
                self.assertEqual(decision.classification, classification)
                text = ui.finding_detail(decision)
                self.assertIn(f'Relevant running jail: {running}', text)
                self.assertIn(f'Retained disabled jail: {disabled}', text)
                self.assertNotIn('not evaluated', text)

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
        result = replace(result, findings=(*result.findings, second), decisions=(*result.decisions, second))
        ui_thread = threading.get_ident()

        def pending(lookback):
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
                    run.assert_called_once_with(timedelta(days=7))
                    old = app.screen
                    self.assertIn("Analyzing coverage…", app.workers.activity_text)
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
                    self.assertEqual(list(current.decisions.values()), list(result.decisions))
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

    async def test_period_changes_are_transactional_and_single_flight(self):
        """Each explicit window owns its request; failure cannot relabel old evidence."""
        entered, release = threading.Event(), threading.Event()
        result = build_findings(*fixture())

        def analyze(lookback):
            if lookback == timedelta(hours=24):
                entered.set()
                if not release.wait(10):
                    raise AssertionError('worker not released')
            evidence = result.pattern_inventory.evidence_snapshot
            return replace(result, pattern_inventory=replace(result.pattern_inventory,
                evidence_snapshot=replace(evidence, lookback=lookback,
                                          requested_since=evidence.collected_at - lookback)))

        with patch('offenders.build_report', side_effect=lambda *, period: replace(report(), period=period)) as build, \
             patch('offenders_geoip_ui.read_state', return_value={}), \
             patch.object(ui, 'run_analysis', side_effect=analyze) as run:
            app = OffendersApp()
            async with app.run_test(size=(120, 50)) as pilot:
                try:
                    await app.workers.wait_for_complete()
                    await pilot.press('p')
                    await app.workers.wait_for_complete()
                    dashboard_period = app._active_period
                    self.assertNotEqual(dashboard_period, '7d')
                    await pilot.press('a')
                    await app.workers.wait_for_complete()
                    screen = app.screen
                    table = screen.query_one(DataTable)
                    self.assertEqual(screen.coverage_period, '7d')
                    self.assertIn('Coverage window: 7d (independent of dashboard period)',
                                  str(screen.query_one('#coverage-summary', Static).content))
                    build.reset_mock()
                    await pilot.press('p')
                    self.assertTrue(await asyncio.to_thread(entered.wait, 3))
                    self.assertEqual(screen.coverage_period, '7d')
                    self.assertIsNone(screen.inventory)
                    self.assertEqual(table.row_count, 0)
                    self.assertEqual(str(screen.query_one('#coverage-detail', Static).content), '')
                    self.assertNotIn('v', screen.active_bindings)
                    with patch.object(app, 'notify') as notify:
                        await pilot.press('p')
                        notify.assert_called_once()
                    self.assertEqual(run.call_count, 2)
                    release.set()
                    await app.workers.wait_for_complete()
                    self.assertEqual(screen.coverage_period, '24h')
                    self.assertEqual(screen.inventory.pattern_inventory.evidence_snapshot.lookback, timedelta(hours=24))
                    self.assertEqual(table.row_count, 1)
                    await pilot.press('p')
                    await app.workers.wait_for_complete()
                    self.assertEqual(screen.coverage_period, '7d')
                    self.assertEqual(run.call_args_list[0].args, (timedelta(days=7),))
                    self.assertEqual([call.args[0] for call in run.call_args_list],
                                     [timedelta(days=7), timedelta(hours=24), timedelta(days=7)])
                    run.side_effect = RuntimeError('requested run failed')
                    await pilot.press('p')
                    await app.workers.wait_for_complete()
                    self.assertEqual(screen.coverage_period, '7d')
                    self.assertIsNone(screen.inventory)
                    self.assertEqual(table.row_count, 0)
                    self.assertFalse(screen.decisions)
                    self.assertEqual(str(screen.query_one('#coverage-detail', Static).content), '')
                    text = str(screen.query_one('#coverage-summary', Static).content)
                    self.assertIn('Analysis unavailable', text)
                    self.assertIn('Requested Coverage window: 24h', text)
                    self.assertNotIn('Requested window:', text)
                    self.assertEqual(app._active_period, dashboard_period)
                    build.assert_not_called()
                finally:
                    release.set()

    async def test_decision_rows_validation_and_local_controls(self):
        """All decisions are inspectable; only candidates route to validation."""
        patterns, coverage = fixture()
        group = patterns.groups[0]
        mixed = build_findings(replace(patterns, groups=(replace(group, signature='z'),
            replace(group, signature='a', event_count=1), replace(group, family='dovecot', signature='b'))), coverage)
        with patch('offenders.build_report', return_value=report()) as build, \
             patch('offenders_geoip_ui.read_state', return_value={}), \
             patch.object(ui, 'run_analysis', return_value=mixed) as run:
            app = OffendersApp()
            async with app.run_test(size=(120, 50)) as pilot:
                await app.workers.wait_for_complete()
                await pilot.press('a')
                await app.workers.wait_for_complete()
                screen = app.screen
                table = screen.query_one(DataTable)
                self.assertEqual(table.row_count, len(mixed.decisions))
                for actual, expected in zip(screen.decisions.values(), mixed.decisions):
                    self.assertIs(actual, expected)
                self.assertEqual(str(table.columns[next(iter(table.columns))].label), 'Disposition')
                for index, decision in enumerate(mixed.decisions):
                    table.move_cursor(row=index)
                    await pilot.pause()
                    self.assertIn(decision.reason, str(screen.query_one('#coverage-detail', Static).content))
                    candidate = decision in mixed.findings
                    self.assertEqual('v' in screen.active_bindings, candidate)
                    if not candidate:
                        with patch.object(app, 'push_screen') as push:
                            await pilot.press('v')
                            screen.action_validate()
                            push.assert_not_called()
                summary = str(screen.query_one('#coverage-summary', Static).content)
                self.assertIn('Below recurrence threshold: 1', summary)
                self.assertIn('Insufficient evidence: 1', summary)
                keys = screen.active_bindings
                self.assertTrue({'p', 'q', 'escape', 'question_mark', 'c', 'x', 't'} <= keys.keys())
                self.assertFalse({'r', 'f', 'a', 'n', 'e', 'g', 'w', 'd'} & keys.keys())
                build.reset_mock()
                await pilot.press('r', 'f', 'a', 'n', 'e', 'g', 'w', 'd')
                self.assertIs(app.screen, screen)
                build.assert_not_called()
                with patch.object(app, 'copy_to_clipboard') as copy:
                    await pilot.press('c', 't', 'x')
                    self.assertEqual(copy.call_count, 2)
                    self.assertEqual(table.cursor_type, 'cell')
                await pilot.press('up')
                self.assertIn(mixed.decisions[1].reason,
                              str(screen.query_one('#coverage-detail', Static).content))
                self.assertNotIn('v', screen.active_bindings)
                self.assertNotIn('v', {key.key for key in screen.query('FooterKey')})
                await pilot.press('q')

    async def test_candidate_routes_and_no_recommendation_rows(self):
        """Existing candidate classes keep their routes; empty headlines retain context."""
        suppressed = build_findings(*fixture(count=1))
        empty = replace(suppressed, decisions=(), pattern_inventory=replace(
            suppressed.pattern_inventory, groups=()))
        with patch('offenders.build_report', return_value=report()), \
             patch('offenders_geoip_ui.read_state', return_value={}), \
             patch.object(ui, 'run_analysis') as run:
            app = OffendersApp()
            async with app.run_test(size=(120, 50)) as pilot:
                await app.workers.wait_for_complete()
                for options, target in (({'disabled': (('spare', 'sshd'),)}, ui.ValidationScreen),
                                        ({'running': (('live', 'sshd'),), 'count': 20}, ui.ValidationScreen),
                                        ({}, ui.CustomCandidateScreen)):
                    inventory = build_findings(*fixture(**options))
                    run.return_value = inventory
                    await pilot.press('a')
                    await app.workers.wait_for_complete()
                    self.assertIn('v', app.screen.active_bindings)
                    await pilot.press('v')
                    self.assertIsInstance(app.screen, target)
                    self.assertIs(app.screen.inventory, inventory)
                    self.assertIs(app.screen.decision, inventory.findings[0])
                    await pilot.press('q', 'q')
                for inventory in (suppressed, empty):
                    run.return_value = inventory
                    await pilot.press('a')
                    await app.workers.wait_for_complete()
                    screen = app.screen
                    self.assertIn('No recommendation', str(screen.query_one('#coverage-summary', Static).content))
                    self.assertEqual(screen.query_one(DataTable).row_count, len(inventory.decisions))
                    self.assertNotIn('v', screen.active_bindings)
                    if inventory.decisions:
                        self.assertIn('Suppressed / not a recommendation',
                                      str(screen.query_one('#coverage-detail', Static).content))
                    else:
                        self.assertIn('No supported pattern was recognized',
                                      str(screen.query_one('#coverage-summary', Static).content))
                    await pilot.press('q')
