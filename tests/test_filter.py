"""Loaded-row matching and real dashboard filtering without acquisition."""
import asyncio
from dataclasses import replace
import threading
import unittest
from unittest.mock import patch

from textual.widgets import DataTable, Input

from offenders import OffendersApp
from offenders_events import BanEvent
from offenders_filter import filter_rows
from offenders_report import Offender
from test_refresh import report


def snapshot():
    """Include older jail terms and unenriched recent addresses."""
    source = report()
    return replace(source, events=[
        BanEvent(source.generated_at, "OldJail", "8.8.8.8", ""),
        *[BanEvent(source.generated_at, "sshd", "1.1.1.1", "")] * 10,
    ], top_offenders=[Offender("8.8.8.8", 42, "Greece", "123", "Straße"),
                      Offender("1.1.1.1", 10, "US", "456", "Other")])


class MatchingTests(unittest.TestCase):
    """One table-driven contract preserves original rows and loaded boundaries."""

    def test_loaded_fields_order_counts_and_last_ten(self):
        source = snapshot()
        for query in (" 8.8 ", "OLDJ", "gREE", "123", "as123", "STRASSE"):
            with self.subTest(query=query):
                rows = filter_rows(source, query)
                self.assertEqual(rows.top_offenders, (source.top_offenders[0],))
                self.assertEqual(rows.top_offenders[0].count, 42)
                self.assertEqual(rows.last_bans, ())
        for query in ("", "  "):
            rows = filter_rows(source, query)
            self.assertEqual(rows.top_offenders, tuple(source.top_offenders))
            self.assertEqual(rows.last_bans, tuple(source.last_10_bans))
        self.assertEqual(filter_rows(source, "AS456").last_bans, tuple(source.last_10_bans))
        self.assertEqual(filter_rows(source, "sshd").last_bans, tuple(source.last_10_bans))
        self.assertEqual(filter_rows(source, "absent").top_offenders, ())
        unmapped = replace(source, top_offenders=[])
        self.assertEqual(filter_rows(unmapped, "1.1").last_bans, tuple(source.last_10_bans))
        self.assertEqual(filter_rows(unmapped, "AS456").last_bans, ())


class DashboardTests(unittest.IsolatedAsyncioTestCase):
    """Exercise keys and worker boundaries with all external work replaced."""

    async def test_filter_navigation_and_refresh_contract(self):
        source = snapshot()
        entered, release = threading.Event(), threading.Event()

        def collect(*, period):
            """Gate a real report worker while the user edits the loaded view."""
            entered.set()
            if not release.wait(10):
                raise AssertionError("collector was not released")
            return replace(source, period=period, top_offenders=[
                replace(source.top_offenders[0], count=99), source.top_offenders[1]])

        with patch("offenders.build_report", return_value=source) as build, \
             patch("offenders_geoip_ui.read_state", return_value={}), \
             patch("offenders_geoip.geoip.lookup", side_effect=AssertionError("extra lookup")), \
             patch("offenders_ip_ui.lookup_output", return_value="offline") as lookup:
            app = OffendersApp()
            async with app.run_test(size=(110, 50)) as pilot:
                await app.workers.wait_for_complete()
                top = app.query_one("#offenders", DataTable)
                last = app.query_one("#last-bans", DataTable)
                field = app.query_one("#filter", Input)
                live = app.query_one("#bans-per-jail", DataTable)
                live_rows = [live.get_row_at(i) for i in range(live.row_count)]
                original = [top.get_row_at(i) for i in range(top.row_count)]
                await pilot.press("f", "a", "s", "1", "2", "3", "enter")
                self.assertIs(app.focused, top)
                self.assertEqual(top.row_count, 1)
                self.assertEqual(top.get_row_at(0)[0], "42")
                self.assertIn("no filter matches", last.get_row_at(0)[3])
                with patch.object(app, "_copy_text") as copy:
                    await pilot.press("c", "t", "x")
                    self.assertEqual(copy.call_count, 2)
                    copy.assert_called_with("42")
                    await pilot.press("t")
                for key, tool in (("w", "whois"), ("d", "rdns")):
                    await pilot.press(key)
                    await app.workers.wait_for_complete()
                    screen, focus = app.screen, app.focused
                    await pilot.press("f")
                    self.assertIs(app.screen, screen)
                    self.assertIs(app.focused, focus)
                    lookup.assert_called_with("8.8.8.8", tool)
                    await pilot.press("escape")
                await pilot.press("enter")
                await app.workers.wait_for_complete()
                self.assertEqual(app.screen.projection.total_bans, 1)
                screen, focus = app.screen, app.focused
                await pilot.press("f")
                self.assertIs(app.screen, screen)
                self.assertIs(app.focused, focus)
                await pilot.press("escape", "f", "escape")
                self.assertEqual(field.value, "")
                self.assertEqual([top.get_row_at(i) for i in range(top.row_count)], original)
                self.assertEqual(build.call_count, 1)
                build.side_effect = collect
                app.action_period()
                try:
                    self.assertTrue(await asyncio.to_thread(entered.wait, 3))
                    await pilot.press("f", "z", "enter")
                    with patch.object(app, "_copy_text") as copy:
                        await pilot.press("enter", "w", "d", "c", "x")
                        copy.assert_not_called()
                    self.assertIs(app.screen, app.default_screen)
                    self.assertEqual(build.call_count, 2)
                    field.value = "as123"
                    await pilot.pause()
                    self.assertEqual(top.get_row_at(0)[0], "42")
                finally:
                    release.set()
                await app.workers.wait_for_complete()
                self.assertEqual(field.value, "as123")
                self.assertEqual(app._active_period, "30d")
                self.assertEqual(top.get_row_at(0)[0], "99")
                app.refresh_report()
                await app.workers.wait_for_complete()
                self.assertEqual(field.value, "as123")
                before = top.get_row_at(0)
                build.side_effect = RuntimeError("failed refresh")
                app.refresh_report()
                await app.workers.wait_for_complete()
                self.assertEqual(top.get_row_at(0), before)
                self.assertEqual(field.value, "as123")
                field.value = ""
                await pilot.pause()
                self.assertEqual(top.row_count, 2)
                self.assertEqual([live.get_row_at(i) for i in range(live.row_count)], live_rows)
                self.assertEqual(build.call_count, 4)
