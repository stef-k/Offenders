"""Manual screen scheduling, stale/empty selection and shared Help/activity contracts."""
import asyncio
from threading import Event
import unittest
from unittest.mock import patch

from textual.widgets import DataTable, Static

from offenders import OffendersApp
from offenders_activity import OffendersFooter
from offenders_enforcement import EnforcementResult, EnforcementRow
from offenders_enforcement_ui import EnforcementScreen
from offenders_help import HelpScreen
from test_refresh import report

RESULT = EnforcementResult((EnforcementRow('guard', '192.0.2.1', 'packet-action', 'nftables',
                                          'confirmed', 'entry-observed', 'entry-observed'),))


class EnforcementScreenTests(unittest.IsolatedAsyncioTestCase):
    """Use real keys and deterministic acquisition barriers, never host commands."""

    def setUp(self):
        """Replace ordinary startup reads while retaining dashboard refresh behavior."""
        for target, value in [('offenders.build_report', report()), ('offenders_geoip_ui.read_state', {})]:
            guard = patch(target, return_value=value)
            guard.start()
            self.addCleanup(guard.stop)

    async def test_manual_mount_recheck_single_flight_and_failure_clears_evidence(self):
        """Startup/timer never acquires enforcement; recheck clears before its worker runs."""
        started, release = Event(), Event()
        self.addCleanup(release.set)
        def failed_check():
            """Synchronize the in-flight state and inject an arbitrary private failure."""
            started.set()
            if not release.wait(5):
                raise RuntimeError('test barrier expired')
            raise RuntimeError('raw private command stderr')
        app = OffendersApp()
        with patch('offenders_enforcement_ui.check_enforcement', return_value=RESULT) as check:
            async with app.run_test() as pilot:
                await app.workers.wait_for_complete()
                app.refresh_report()  # Same callback used by the report timer.
                await app.workers.wait_for_complete()
                check.assert_not_called()
                committed = app._last_report
                await pilot.press('n')
                await app.workers.wait_for_complete()
                screen = app.screen
                self.assertIsInstance(screen, EnforcementScreen)
                self.assertEqual(check.call_count, 1)
                table = screen.query_one(DataTable)
                self.assertEqual(table.row_count, 1)
                self.assertIn('Backend evidence: entry-observed', str(screen.query_one('#enforcement-detail', Static).content))
                old_event = DataTable.RowHighlighted(table, table.coordinate_to_cell_key((0, 0)).row_key, 0)
                check.side_effect = failed_check
                await pilot.press('r')
                self.assertTrue(await asyncio.to_thread(started.wait, 2))
                self.assertEqual(table.row_count, 0)
                self.assertEqual(screen.rows, {})
                self.assertIsNone(screen.result)
                screen.highlight_row(old_event)
                self.assertEqual(str(screen.query_one('#enforcement-detail', Static).content), '')
                await pilot.press('r', 'r', 'n')
                self.assertIs(app.screen, screen)
                self.assertEqual(check.call_count, 2)
                self.assertIn('Checking enforcement', app.workers.activity_text)
                release.set()
                await app.workers.wait_for_complete()
                summary = str(screen.query_one('#enforcement-summary', Static).content)
                self.assertIn('Check unavailable: check-unavailable', summary)
                self.assertNotIn('private', summary)
                self.assertEqual(table.row_count, 0)
                self.assertIs(app._last_report, committed)
                await pilot.press('q')
                self.assertIs(app.screen, app.default_screen)

    async def test_close_cancels_and_ignores_late_delivery(self):
        """A cancelled thread cannot repopulate a closed screen or a later screen."""
        started, release, finished = Event(), Event(), Event()
        self.addCleanup(release.set)
        def delayed_check():
            """Complete only after the UI has explicitly closed."""
            started.set()
            release.wait(5)
            finished.set()
            return RESULT
        app = OffendersApp()
        with patch('offenders_enforcement_ui.check_enforcement', side_effect=delayed_check):
            async with app.run_test() as pilot:
                await app.workers.wait_for_complete()
                await pilot.press('n')
                self.assertTrue(await asyncio.to_thread(started.wait, 2))
                screen, worker = app.screen, app.screen._worker
                await pilot.press('escape')
                self.assertTrue(worker.is_cancelled)
                self.assertTrue(screen._delivery_closed)
                screen._complete(RESULT, worker)
                self.assertIsNone(screen.result)
                release.set()
                self.assertTrue(await asyncio.to_thread(finished.wait, 2))
                await pilot.pause()
                self.assertIs(app.screen, app.default_screen)
                self.assertIsNone(screen.result)

    async def test_help_empty_selection_and_stale_same_identity_event(self):
        """Help starts no new check; old-generation row keys cannot select new evidence."""
        app = OffendersApp()
        with patch('offenders_enforcement_ui.check_enforcement', return_value=RESULT) as check:
            async with app.run_test(size=(90, 30)) as pilot:
                await app.workers.wait_for_complete()
                await pilot.press('n')
                await app.workers.wait_for_complete()
                screen, table = app.screen, app.screen.query_one(DataTable)
                self.assertEqual(screen.query_one(OffendersFooter).region.height, 1)
                event = DataTable.RowHighlighted(table, table.coordinate_to_cell_key((0, 0)).row_key, 0)
                await pilot.press('?')
                self.assertIsInstance(app.screen, HelpScreen)
                text = str(app.screen.query_one('#help-context', Static).content)
                self.assertIn('Current screen: Enforcement', text)
                self.assertIn('Recheck', text)
                await pilot.press('r', 'n', 'q')
                self.assertIs(app.screen, screen)
                self.assertEqual(check.call_count, 1)
                check.return_value = EnforcementResult((EnforcementRow('guard', '192.0.2.1', 'packet-action', 'nftables',
                                                                        'missing', 'ban-entry-absent', 'ban-entry-absent'),))
                await pilot.press('r')
                await app.workers.wait_for_complete()
                screen.query_one('#enforcement-detail', Static).update('selection unchanged')
                screen.highlight_row(event)
                self.assertEqual(str(screen.query_one('#enforcement-detail', Static).content), 'selection unchanged')
                check.return_value = EnforcementResult()
                await pilot.press('r')
                await app.workers.wait_for_complete()
                self.assertEqual(table.row_count, 0)
                table.move_cursor(row=-1)
                screen.highlight_row(event)
                await pilot.press('enter', 'up', 'down')
                self.assertIn('No active jails', str(screen.query_one('#enforcement-summary', Static).content))

    async def test_namespace_unavailable_result_leaves_dashboard_healthy(self):
        """Missing enforcement evidence is local to the manual view."""
        result = EnforcementResult((EnforcementRow('guard', '192.0.2.1', 'packet-action', 'nftables',
                                                   reason='namespace-unavailable'),))
        app = OffendersApp()
        with patch('offenders_enforcement_ui.check_enforcement', return_value=result):
            async with app.run_test() as pilot:
                await app.workers.wait_for_complete()
                committed = app._last_report
                await pilot.press('n')
                await app.workers.wait_for_complete()
                self.assertEqual(app.screen.result.rows[0].outcome, 'unverifiable')
                await pilot.press('escape')
                self.assertIs(app._last_report, committed)
                self.assertNotIn('Degraded', str(app.query_one('#summary', Static).content))
