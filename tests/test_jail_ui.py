"""Offline keyboard navigation and successful-report jail detail contracts."""

import datetime as dt
from dataclasses import replace
import unittest
from unittest.mock import patch

from textual.containers import VerticalScroll
from textual.widgets import DataTable, Static

from offenders import OffendersApp
from offenders_fail2ban import JailStatus
from offenders_jail_ui import JailDetailScreen, jail_details
from offenders_report import Report


def snapshot(*statuses, minute=0, period="7d"):
    """Build distinct reports without log or Fail2Ban access."""
    return Report(dt.datetime(2026, 9, 27, 12, minute), period, None, [], [], list(statuses))


class JailDetailTests(unittest.IsolatedAsyncioTestCase):
    """Exercise real screen routing with only collection replaced."""

    def test_values_are_literal_and_unavailable_is_not_zero(self):
        """Raw special settings and zero counters retain their actual meaning."""
        jail = JailStatus("[red]sshd", 0, 0, 0, 0, ("192.0.2.1",), bantime=-1,
                          findtime=0, maxretry=3, backend="systemd", filter_name="sshd")
        text = jail_details(jail.name, snapshot(jail)).plain
        self.assertIn("Jail: [red]sshd", text)
        self.assertIn("Currently failed: 0", text)
        self.assertIn("Total banned: 0", text)
        self.assertIn("Bantime (seconds): -1", text)
        self.assertIn("Findtime (seconds): 0", text)
        self.assertIn("Maxretry: 3", text)
        self.assertIn("Backend: systemd", text)
        self.assertIn("Filter: sshd", text)
        self.assertNotIn("192.0.2.1", text)

    async def test_keyboard_refresh_period_failure_and_disappearance(self):
        """One flow proves selection, no open-time work, and last-known-good detail."""
        ssh = JailStatus("sshd", 0, 0, 0, 0, ())
        web = JailStatus("web", 1, 2, 2, 3, ())
        initial = snapshot(ssh, web)
        updated = snapshot(replace(ssh, currently_banned=4), web, minute=1)
        with patch("offenders.build_report", return_value=initial) as build, \
             patch("offenders_geoip_ui.read_state", return_value={}):
            app = OffendersApp()
            async with app.run_test(size=(90, 20)) as pilot:
                await app.workers.wait_for_complete()
                table = app.query_one("#bans-per-jail", DataTable)
                # Tab from the first table to the existing jail navigation surface.
                app.query_one("#offenders", DataTable).focus()
                await pilot.press("tab", "down", "enter")
                detail = app.screen
                self.assertIsInstance(detail, JailDetailScreen)
                self.assertEqual(detail.jail, "sshd")
                build.assert_called_once_with(period="7d")
                content = detail.query_one("#jail-details", Static)
                self.assertIn("Currently banned: 0", str(content.content))
                self.assertIn("Bantime (seconds): Unavailable", str(content.content))
                self.assertIn("Backend: Unavailable", str(content.content))
                self.assertIn("Filter: Unavailable", str(content.content))
                await pilot.press("escape")
                self.assertIs(app.focused, table)
                self.assertEqual(table.get_row_at(table.cursor_row)[0], "sshd")
                await pilot.press("enter")
                detail = app.screen
                content = detail.query_one("#jail-details", Static)
                scroll = detail.query_one(VerticalScroll)
                scroll.focus()
                await pilot.press("down")
                await pilot.pause()
                position = scroll.scroll_y
                build.return_value = updated
                await pilot.press("r")
                await app.workers.wait_for_complete()
                self.assertIs(app.screen, detail)
                self.assertIs(app.focused, scroll)
                self.assertEqual(scroll.scroll_y, position)
                self.assertIn("Currently banned: 4", str(content.content))
                self.assertIn("12:01:00", str(content.content))
                self.assertEqual(table.get_row_at(table.cursor_row)[0], "sshd")
                self.assertEqual(table.cursor_row, 0)
                build.return_value = replace(updated, period="30d", generated_at=dt.datetime(2026, 9, 27, 12, 2))
                await pilot.press("p")
                await app.workers.wait_for_complete()
                build.assert_called_with(period="30d")
                self.assertIs(app.screen, detail)
                self.assertEqual(detail.jail, "sshd")
                self.assertIn("Historical period: 30d", str(content.content))
                before = str(content.content)
                build.side_effect = RuntimeError("collection failed")
                await pilot.press("p")
                await app.workers.wait_for_complete()
                self.assertEqual(str(content.content), before)
                self.assertEqual(app._active_period, "30d")
                self.assertIn("Degraded", str(app.query_one("#summary", Static).content))
                await pilot.press("q")
                self.assertIs(app.focused, table)
                self.assertEqual(table.get_row_at(table.cursor_row)[0], "sshd")
                # Cell mode uses the same jail identity path.
                await pilot.press("t", "enter")
                detail = app.screen
                self.assertEqual(detail.jail, "sshd")
                build.side_effect = None
                build.return_value = snapshot(web, minute=3, period="30d")
                await pilot.press("r")
                await app.workers.wait_for_complete()
                text = str(detail.query_one("#jail-details", Static).content)
                self.assertIn("Jail not active in latest successful refresh", text)
                self.assertIn("12:03:00", text)
                self.assertNotIn("Currently banned:", text)
                await pilot.press("escape")
                self.assertIs(app.focused, table)
                self.assertEqual(table.get_row_at(table.cursor_row)[0], "web")
                build.return_value = snapshot(period="30d")
                await pilot.press("r")
                await app.workers.wait_for_complete()
                await pilot.press("enter")
                self.assertIs(app.screen, app.default_screen)
                self.assertEqual(build.call_count, 6)
