"""One real Textual flow for routing, explicit work, copy and stale delivery."""
import asyncio
from dataclasses import replace
import threading
import unittest
from unittest.mock import patch

from textual.widgets import Static
from offenders import OffendersApp
import offenders_candidate as backend
import offenders_candidate_ui as ui
import offenders_recommendations_ui as coverage_ui
from test_candidate import matched, web_inventory
from test_refresh import report


class CandidateScreenTests(unittest.IsolatedAsyncioTestCase):
    """Exercise the review screen without host commands or clipboard side effects."""

    async def test_explicit_worker_review_copy_withhold_and_close(self):
        inv = web_inventory()
        decision = inv.findings[0]
        with patch.object(backend, 'validate_custom', side_effect=matched):
            result = backend.generate_candidate(inv, decision)
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        ui_thread = threading.get_ident()

        def pending(actual_inventory, actual_decision):
            self.assertNotEqual(threading.get_ident(), ui_thread)
            self.assertIs(actual_inventory, inv)
            self.assertIs(actual_decision, decision)
            entered.set()
            try:
                if not release.wait(10):
                    raise AssertionError('worker not released')
                return result
            finally:
                finished.set()

        with patch('offenders.build_report', return_value=report()), \
             patch('offenders_geoip_ui.read_state', return_value={}), \
             patch.object(coverage_ui, 'run_analysis', return_value=inv) as analysis, \
             patch.object(ui, 'generate_candidate', side_effect=pending) as run:
            app = OffendersApp()
            async with app.run_test(size=(120, 50)) as pilot:
                try:
                    await app.workers.wait_for_complete()
                    await pilot.press('a')
                    await app.workers.wait_for_complete()
                    await pilot.press('v')
                    screen = app.screen
                    self.assertIsInstance(screen, ui.CustomCandidateScreen)
                    self.assertIn(ui.INITIAL, str(screen.query_one(Static).content))
                    run.assert_not_called()
                    with patch.object(app, 'copy_to_clipboard') as copy:
                        await pilot.press('c', 'v')
                        self.assertTrue(await asyncio.to_thread(entered.wait, 3))
                        self.assertIn('Generating and validating', str(screen.query_one(Static).content))
                        await pilot.press('v', 'c')
                        self.assertEqual(run.call_count, 1)
                        copy.assert_not_called()
                        await pilot.press('escape')
                        release.set()
                        self.assertTrue(await asyncio.to_thread(finished.wait, 3))
                        run.side_effect = None
                        run.return_value = result
                        await pilot.press('v', 'v')
                        await app.workers.wait_for_complete()
                        self.assertIsNone(screen.result)
                        self.assertIs(app.screen.result, result)
                        detail = str(app.screen.query_one(Static).content)
                        for value in ('Candidate for operator review', ui.CAVEATS, '[Definition]', result.filter_sha256):
                            self.assertIn(value, detail)
                        await pilot.press('c')
                        copy.assert_called_once_with(ui.copy_text(result))
                        self.assertIn(result.filter_text, copy.call_args.args[0])
                        copy.side_effect = RuntimeError('clipboard absent')
                        with patch('builtins.print') as fallback:
                            await pilot.press('c')
                            fallback.assert_called_once_with(ui.copy_text(result))
                        copy.reset_mock()
                        run.return_value = replace(result, state='withheld', filter_text=None, jail_text=None,
                                                   reason='target miss', limitations=('retained limit',))
                        await pilot.press('v')
                        await app.workers.wait_for_complete()
                        await pilot.press('c')
                        copy.assert_not_called()
                        detail = str(app.screen.query_one(Static).content)
                        self.assertIn('Custom candidate withheld', detail)
                        self.assertIn('retained limit', detail)
                        self.assertNotIn('[Definition]', detail)
                        analysis.assert_called_once()
                finally:
                    release.set()
