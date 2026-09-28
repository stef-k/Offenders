"""Real dashboard export routing, retained snapshots, background work and copy."""
import asyncio
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

from textual.widgets import Input, Static

from offenders import OffendersApp
from offenders_export_ui import ExportScreen
from test_refresh import report, rendered


class ExportUITests(unittest.IsolatedAsyncioTestCase):
    """Use causal worker barriers without host reads or filesystem writes."""

    async def test_committed_snapshot_worker_path_copy_and_failure(self):
        source = report()
        entered, release = threading.Event(), threading.Event()
        ui_thread = threading.get_ident()
        path = Path('/tmp/reports/exact bundle')

        def write(actual, root):
            self.assertIs(actual, source)
            self.assertNotEqual(threading.get_ident(), ui_thread)
            entered.set()
            if not release.wait(5):
                raise AssertionError('worker not released')
            return path

        with patch('offenders.build_report', return_value=source) as build, \
             patch('offenders_geoip_ui.read_state', return_value={}), \
             patch('offenders_export_ui.export_report', side_effect=write) as export:
            app = OffendersApp()
            async with app.run_test(size=(120, 50)) as pilot:
                await app.workers.wait_for_complete()
                app.query_one('#filter', Input).value = 'ssh'
                app.action_view()
                # A failed requested period leaves the original committed report.
                build.side_effect = RuntimeError('refresh failed')
                await pilot.press('p')
                await app.workers.wait_for_complete()
                before = rendered(app)
                calls = build.call_count
                await pilot.press('e')
                screen = app.screen
                self.assertIsInstance(screen, ExportScreen)
                self.assertIs(screen.report, source)
                detail = str(screen.query_one(Static).content)
                self.assertIn('"ssh" is display-only', detail)
                self.assertIn(source.generated_at.isoformat(), detail)
                export.assert_not_called()
                with patch.object(app, 'copy_to_clipboard') as copy:
                    try:
                        await pilot.press('c', 'e')
                        self.assertTrue(await asyncio.to_thread(entered.wait, 3))
                        self.assertIn('Exporting…', app.workers.activity_text)
                        await pilot.press('e', 'c')
                        self.assertEqual(export.call_count, 1)
                        copy.assert_not_called()
                    finally:
                        release.set()
                    await app.workers.wait_for_complete()
                    self.assertEqual(str(screen.query_one('#export-status', Static).content), 'Export complete')
                    self.assertEqual(str(screen.query_one('#export-path', Static).content), str(path))
                    await pilot.press('c')
                    copy.assert_called_once_with(str(path))
                    copy.side_effect = RuntimeError('no clipboard')
                    with patch('builtins.print') as fallback:
                        await pilot.press('c')
                        fallback.assert_called_once_with(str(path))
                    export.side_effect = PermissionError('denied')
                    await pilot.press('e')
                    await app.workers.wait_for_complete()
                    self.assertIsNone(screen.path)
                    self.assertIn('Export failed: denied', str(screen.query_one('#export-status', Static).content))
                self.assertEqual(build.call_count, calls)
                await pilot.press('q')
                self.assertIs(app.screen, app.default_screen)
                self.assertIs(app._last_report, source)
                self.assertEqual(rendered(app), before)

    async def test_no_successful_report_does_not_open_export(self):
        with patch('offenders.build_report', side_effect=RuntimeError('unavailable')), \
             patch('offenders_geoip_ui.read_state', return_value={}), \
             patch('offenders_export_ui.export_report') as export:
            app = OffendersApp()
            async with app.run_test() as pilot:
                await app.workers.wait_for_complete()
                with patch.object(app, 'notify') as notify:
                    await pilot.press('e')
                    notify.assert_called_once_with('No successful report to export', timeout=2.0)
                self.assertIs(app.screen, app.default_screen)
                export.assert_not_called()
