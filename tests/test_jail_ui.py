"""Offline keyboard navigation and successful-report jail detail contracts."""

import datetime as dt
from dataclasses import replace
import unittest
from unittest.mock import patch

from textual.containers import VerticalScroll
from textual.widgets import DataTable, Static

from offenders import OffendersApp
from offenders_events import BanEvent
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
        self.assertIn("192.0.2.1", text)

    def test_optional_identities_are_only_shown_when_collected(self):
        """Omit absent identities independently; even empty strings are literal."""
        jail = JailStatus("sshd", 0, 0, 0, 0, ())
        for backend, filter_name, expected in (
            (None, None, []),
            ("[blue]systemd", None, ["Backend: [blue]systemd"]),
            (None, "[green]sshd", ["Filter: [green]sshd"]),
            ("", "", ["Backend: ", "Filter: "]),
        ):
            with self.subTest(backend=backend, filter_name=filter_name):
                status = replace(jail, backend=backend, filter_name=filter_name)
                lines = jail_details(jail.name, snapshot(status)).plain.splitlines()
                self.assertEqual([line for line in lines if line.startswith(("Backend:", "Filter:"))],
                                 expected)

    def test_numeric_settings_distinguish_zero_from_unavailable(self):
        """Keep all acquired numeric settings visible, including zero and None."""
        jail = JailStatus("sshd", 0, 0, 0, 0, ())
        for value, expected in ((0, "0"), (None, "Unavailable")):
            with self.subTest(value=value):
                status = replace(jail, bantime=value, findtime=value, maxretry=value)
                lines = jail_details(jail.name, snapshot(status)).plain.splitlines()
                for label in ("Bantime (seconds)", "Findtime (seconds)", "Maxretry"):
                    self.assertIn(f"{label}: {expected}", lines)

    async def test_keyboard_refresh_period_failure_and_disappearance(self):
        """One flow proves selection, no open-time work, and last-known-good detail."""
        ssh = JailStatus("sshd", 0, 0, 0, 0, ())
        web = JailStatus("web", 1, 2, 2, 3, ())
        events = [
            BanEvent(dt.datetime(2026, 9, 27, 10) + dt.timedelta(seconds=i),
                     "sshd", "10.0.0.1" if i % 2 else "2001:db8::1", "not parsed")
            for i in range(105)
        ]
        # Keep repeated records, and exclude a similarly named jail exactly.
        events += [events[-1], replace(events[-1], jail="sshd-other")]
        initial = replace(snapshot(ssh, web), events=events)
        changed_events = [events[0], replace(events[1], timestamp=dt.datetime(2026, 9, 27, 12))]
        updated = replace(snapshot(replace(ssh, currently_banned=4,
                                           banned_ips=("192.0.2.9", "2001:db8::9")),
                                   web, minute=1), events=changed_events)
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
                history = detail.query_one("#jail-history", DataTable)
                expected = sorted(events[:-1], key=lambda event: event.timestamp, reverse=True)
                def rows():
                    """Read visible product rows without relying on table internals."""
                    return [history.get_row_at(i) for i in range(history.row_count)]
                for limit in (10, 50, 100, 106, 106):
                    self.assertEqual(rows(), [
                        [event.timestamp.strftime("%Y-%m-%d"),
                         event.timestamp.strftime("%H:%M:%S"), event.ip]
                        for event in expected[:limit]
                    ])
                    await pilot.press("e", "down")
                build.assert_called_once_with(period="7d")
                self.assertIn("(none)", str(content.content))
                self.assertNotIn("2001:db8::1", str(content.content))
                self.assertIn("Currently banned: 0", str(content.content))
                self.assertIn("Bantime (seconds): Unavailable", str(content.content))
                self.assertNotIn("Backend:", str(content.content))
                self.assertNotIn("Filter:", str(content.content))
                await pilot.press("escape")
                self.assertIs(app.focused, table)
                self.assertEqual(table.get_row_at(table.cursor_row)[0], "sshd")
                await pilot.press("enter")
                detail = app.screen
                content = detail.query_one("#jail-details", Static)
                history = detail.query_one("#jail-history", DataTable)
                self.assertEqual(history.row_count, 10)
                await pilot.press("e")
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
                self.assertEqual(detail.history_level, 1)
                self.assertEqual(rows(), [["2026-09-27", "12:00:00", "10.0.0.1"],
                                          ["2026-09-27", "10:00:00", "2001:db8::1"]])
                self.assertIn("192.0.2.9", str(content.content))
                self.assertIn("2001:db8::9", str(content.content))
                self.assertIn("Currently banned: 4", str(content.content))
                self.assertIn("12:01:00", str(content.content))
                self.assertEqual(table.get_row_at(table.cursor_row)[0], "sshd")
                self.assertEqual(table.cursor_row, 0)
                build.return_value = replace(updated, events=events[:60], period="30d", generated_at=dt.datetime(2026, 9, 27, 12, 2))
                await pilot.press("p")
                await app.workers.wait_for_complete()
                build.assert_called_with(period="30d")
                self.assertIs(app.screen, detail)
                self.assertEqual(detail.jail, "sshd")
                self.assertIn("Historical period: 30d", str(content.content))
                self.assertEqual(history.row_count, 50)
                self.assertEqual(detail.history_level, 1)
                before_rows = rows()
                before_summary = str(detail.query_one("#jail-history-summary", Static).content)
                before = str(content.content)
                build.side_effect = RuntimeError("collection failed")
                await pilot.press("p")
                await app.workers.wait_for_complete()
                self.assertEqual(str(content.content), before)
                self.assertEqual(rows(), before_rows)
                self.assertEqual(detail.history_level, 1)
                self.assertEqual(str(detail.query_one("#jail-history-summary", Static).content),
                                 before_summary)
                self.assertEqual(app._active_period, "30d")
                self.assertIn("Degraded", str(app.query_one("#summary", Static).content))
                await pilot.press("q")
                self.assertIs(app.focused, table)
                self.assertEqual(table.get_row_at(table.cursor_row)[0], "sshd")
                recent = app.query_one("#last-bans", DataTable)
                self.assertEqual(recent.row_count, 10)
                self.assertEqual([recent.get_row_at(i)[-1] for i in range(10)],
                                 [event.ip for event in events[50:60]])
                # Cell mode uses the same jail identity path.
                await pilot.press("t", "enter")
                detail = app.screen
                self.assertEqual(detail.jail, "sshd")
                build.side_effect = None
                build.return_value = replace(snapshot(web, minute=3, period="30d"), events=events[:3])
                await pilot.press("r")
                await app.workers.wait_for_complete()
                text = str(detail.query_one("#jail-details", Static).content)
                self.assertIn("Jail not active in latest successful refresh", text)
                self.assertIn("12:03:00", text)
                self.assertNotIn("Currently banned:", text)
                self.assertIn("Unavailable — jail not active", text)
                self.assertEqual(detail.query_one("#jail-history", DataTable).row_count, 3)
                build.return_value = snapshot(web, minute=4, period="30d")
                await pilot.press("r")
                await app.workers.wait_for_complete()
                self.assertEqual(detail.query_one("#jail-history", DataTable).row_count, 0)
                detail.query_one("#jail-history", DataTable).focus()
                with patch.object(app, "_copy_text") as copy:
                    await pilot.press("c", "x", "t", "c")
                    copy.assert_not_called()
                self.assertIn("No historical bans", str(detail.query_one(
                    "#jail-history-summary", Static).content))
                await pilot.press("escape")
                self.assertIs(app.focused, table)
                self.assertEqual(table.get_row_at(table.cursor_row)[0], "web")
                build.return_value = snapshot(period="30d")
                await pilot.press("r")
                await app.workers.wait_for_complete()
                await pilot.press("enter")
                self.assertIs(app.screen, app.default_screen)
                self.assertEqual(build.call_count, 7)

    async def test_back_reselects_jail_that_reappeared(self):
        """A temporary absence must not turn a fallback row into the viewed jail."""
        ssh = JailStatus("sshd", 0, 0, 0, 0, ())
        web = replace(ssh, name="web", currently_banned=2)
        with patch("offenders.build_report", return_value=snapshot(ssh, web)) as build, \
             patch("offenders_geoip_ui.read_state", return_value={}):
            app = OffendersApp()
            async with app.run_test() as pilot:
                await app.workers.wait_for_complete()
                table = app.query_one("#bans-per-jail", DataTable)
                table.focus()
                await pilot.press("down", "enter")
                for statuses in [(web,), (ssh, web)]:
                    build.return_value = snapshot(*statuses)
                    await pilot.press("r")
                    await app.workers.wait_for_complete()
                await pilot.press("escape")
                self.assertIs(app.focused, table)
                self.assertEqual(table.get_row_at(table.cursor_row)[0], "sshd")
