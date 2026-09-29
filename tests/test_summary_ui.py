"""Real Textual summary interaction with causal worker gates and offline fixtures."""
import asyncio
from dataclasses import replace
import threading
import unittest
from unittest.mock import patch

from textual.widgets import DataTable, Input

from offenders import OffendersApp
from offenders_aggregate import aggregate_report
from test_aggregate import source


class SummaryTests(unittest.IsolatedAsyncioTestCase):
    """Exercise view/query ownership without host acquisition or command execution."""

    async def test_views_actions_and_refresh(self):
        data, facts = source()
        ui_thread = threading.get_ident()

        def lookup(ip):
            self.assertNotEqual(threading.get_ident(), ui_thread)
            return facts[ip]

        with patch("offenders.build_report", return_value=data) as build, \
             patch("offenders_geoip_ui.read_state", return_value={}), \
             patch("offenders_geoip.geoip.lookup", side_effect=lookup) as local, \
             patch("offenders_ip_ui.lookup_output", return_value="offline") as command:
            app = OffendersApp()
            async with app.run_test(size=(110, 50)) as pilot:
                await app.workers.wait_for_complete()
                local.assert_not_called()
                table = app.query_one("#offenders", DataTable)
                field = app.query_one("#filter", Input)
                await pilot.press("v")
                await app.workers.wait_for_complete()
                self.assertEqual(app.summary_view.mode, "ASN")
                self.assertEqual(table.get_row_at(0), ["3", "2", "AS123", "Straße"])
                with patch.object(app, "_copy_text") as copy:
                    await pilot.press("enter", "w", "d", "c", "t", "x", "t")
                    self.assertEqual(copy.call_count, 2)
                self.assertIs(app.screen, app.default_screen)
                command.assert_not_called()
                await pilot.press("v")
                self.assertEqual(app.summary_view.mode, "Country")
                self.assertEqual(table.get_row_at(0), ["3", "2", "GR"])
                self.assertEqual(local.call_count, 3)
                self.assertEqual(build.call_count, 1)
                field.value = "8.8"
                await pilot.pause()
                self.assertEqual(table.get_row_at(0)[0], "3")
                last = app.query_one("#last-bans", DataTable)
                last.focus()
                for key in ("enter", "w", "d"):
                    await pilot.press(key)
                    await app.workers.wait_for_complete()
                    screen = app.screen
                    await pilot.press("v")
                    self.assertIs(app.screen, screen)
                    self.assertEqual(app.summary_view.mode, "Country")
                    await pilot.press("escape")
                self.assertEqual(command.call_count, 2)
                table.focus()
                build.return_value = replace(data, period="30d", events=data.events * 2)
                await pilot.press("p")
                await app.workers.wait_for_complete()
                self.assertEqual(app._active_period, "30d")
                self.assertEqual(field.value, "8.8")
                self.assertEqual(table.get_row_at(0)[0], "6")
                self.assertEqual(local.call_count, 6)
                snapshot = app.summary_view.snapshot
                build.side_effect = RuntimeError("offline failure")
                await pilot.press("r")
                await app.workers.wait_for_complete()
                self.assertIs(app.summary_view.snapshot, snapshot)
                self.assertEqual(local.call_count, 6)
                await pilot.press("v")
                self.assertEqual(app.summary_view.mode, "IP")
                self.assertEqual(table.get_row_at(0)[1], "8.8.8.8")

    async def test_pending_filter_stale_completion_and_return_to_ip(self):
        data, facts = source()
        entered, release = threading.Event(), threading.Event()
        calls = []

        def project(report, lookup):
            calls.append(report)
            if report is data:
                entered.set()
                if not release.wait(10):
                    raise AssertionError("projection not released")
            return aggregate_report(report, facts.__getitem__)

        with patch("offenders.build_report", return_value=data) as build, \
             patch("offenders_geoip_ui.read_state", return_value={}), \
             patch("offenders_summary_ui.aggregate_report", side_effect=project):
            app = OffendersApp()
            async with app.run_test(size=(110, 50)) as pilot:
                await app.workers.wait_for_complete()
                table = app.query_one("#offenders", DataTable)
                field = app.query_one("#filter", Input)
                try:
                    await pilot.press("v")
                    self.assertTrue(await asyncio.to_thread(entered.wait, 3))
                    self.assertEqual(table.get_row_at(0)[0], "(loading)")
                    await pilot.press("v")
                    field.value = "8.8"
                    await pilot.pause()
                    self.assertEqual(len(calls), 1)
                    await pilot.press("v")
                    release.set()
                    await app.workers.wait_for_complete()
                    self.assertEqual(table.get_row_at(0)[1], "8.8.8.8")
                    await pilot.press("v")
                    self.assertEqual(table.get_row_at(0)[0], "3")
                    self.assertEqual(len(calls), 1)
                    # Start another blocked old report, then let a newer one finish first.
                    entered.clear()
                    release.clear()
                    intermediate = replace(data)
                    app._apply_report(intermediate)
                    await app.workers.wait_for_complete()
                    app._apply_report(data)
                    self.assertTrue(await asyncio.to_thread(entered.wait, 3))
                    newest = replace(data, events=data.events * 3)
                    completed = asyncio.Event()
                    original_complete = app.summary_view._complete

                    def complete(report, snapshot, worker=None):
                        original_complete(report, snapshot, worker)
                        if report is newest:
                            completed.set()

                    with patch.object(app.summary_view, "_complete", side_effect=complete):
                        build.return_value = newest
                        app.refresh_report()
                        await asyncio.wait_for(completed.wait(), 3)
                    release.set()
                    await app.workers.wait_for_complete()
                    self.assertIs(app.summary_view.report, newest)
                    self.assertEqual(table.get_row_at(0)[0], "9")
                    self.assertEqual(field.value, "8.8")
                    field.value = "missing"
                    await pilot.pause()
                    with patch.object(app, "_copy_text") as copy:
                        await pilot.press("enter", "w", "d", "c")
                        copy.assert_not_called()
                    self.assertIn("no filter matches", table.get_row_at(0)[0])
                finally:
                    release.set()
