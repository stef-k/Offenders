"""Offline interaction proof for explicit validation and screen-owned delivery."""
import asyncio
import threading
import unittest
from unittest.mock import patch

from textual.widgets import Static

from offenders import OffendersApp
import offenders_recommendations_ui as coverage_ui
import offenders_validation_ui as ui
from offenders_validation import FilterValidation, SampleResult
from test_refresh import report
from test_validation import inventory


class ValidationScreenTests(unittest.IsolatedAsyncioTestCase):
    """One real Textual flow covers selection, worker exclusion and stale delivery."""

    async def test_explicit_selection_worker_and_closed_delivery(self):
        inv = inventory(disabled=(('first', 'sshd'), ('second', 'sshd')))
        decision = inv.findings[0]
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        ui_thread = threading.get_ident()
        result = FilterValidation(decision, 'existing', jail_name='second', filter_stem='sshd',
            target=SampleResult(3, 3, 12, 3, 1, 1, 1, ('[bold]literal[/bold]',)),
            state='partial', limitations=('retained limitation',))

        def pending(actual_inventory, actual_decision, target):
            self.assertNotEqual(threading.get_ident(), ui_thread)
            self.assertIs(actual_inventory, inv)
            self.assertIs(actual_decision, decision)
            self.assertIs(target, decision.disabled_candidates[1])
            entered.set()
            try:
                if not release.wait(10):
                    raise AssertionError('validation worker not released')
                return result
            finally:
                finished.set()

        with patch('offenders.build_report', return_value=report()), \
             patch('offenders_geoip_ui.read_state', return_value={}), \
             patch.object(coverage_ui, 'run_analysis', return_value=inv) as analysis, \
             patch.object(ui, 'validate_existing', side_effect=pending) as run:
            app = OffendersApp()
            async with app.run_test(size=(120, 50)) as pilot:
                try:
                    await app.workers.wait_for_complete()
                    await pilot.press('v')
                    run.assert_not_called()
                    await pilot.press('a')
                    await app.workers.wait_for_complete()
                    run.assert_not_called()
                    await pilot.press('v', 'down')
                    run.assert_not_called()
                    screen = app.screen
                    self.assertIs(screen.targets[1], decision.disabled_candidates[1])
                    await pilot.press('v')
                    self.assertTrue(await asyncio.to_thread(entered.wait, 3))
                    self.assertIn('Validating… second', str(screen.query_one('#validation-detail', Static).content))
                    await pilot.press('v', 'enter')
                    self.assertEqual(run.call_count, 1)
                    await pilot.press('escape')
                    release.set()
                    self.assertTrue(await asyncio.to_thread(finished.wait, 3))
                    run.side_effect = None
                    run.return_value = result
                    await pilot.press('v', 'v')
                    await app.workers.wait_for_complete()
                    self.assertIsNone(screen.result)
                    self.assertIs(app.screen.result, result)
                    text = str(app.screen.query_one('#validation-detail', Static).content)
                    for value in ('Validation: partial', 'Tested lines: 3; matched: 1; missed: 1; ignored: 1',
                                  '[bold]literal[/bold]', 'retained limitation', ui.INTERPRETATION):
                        self.assertIn(value, text)
                    analysis.assert_called_once()
                    await pilot.press('q')
                    run.side_effect = RuntimeError('fixture failure')
                    await pilot.press('v', 'enter')
                    await app.workers.wait_for_complete()
                    self.assertIn('Validation unavailable', str(app.screen.query_one('#validation-detail', Static).content))
                    await pilot.press('q', 'q')
                    analysis.return_value = inventory(custom=True)
                    await pilot.press('a')
                    await app.workers.wait_for_complete()
                    await pilot.press('v')
                    self.assertIn(ui.NO_TARGET, str(app.screen.query_one('#validation-detail', Static).content))
                    calls = run.call_count
                    await pilot.press('v', 'enter')
                    self.assertEqual(run.call_count, calls)
                    await pilot.press('q')
                finally:
                    release.set()
