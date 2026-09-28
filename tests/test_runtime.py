"""Exercise dashboard startup against the supported Textual dependency."""

import datetime as dt
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch

from textual.widgets import DataTable, Static

import offenders
from offenders_fail2ban import JailStatus
from offenders_help import HelpScreen
from offenders_events import BanEvent
from offenders_report import Offender, Report


class RuntimeTests(unittest.IsolatedAsyncioTestCase):
    """Keep runtime checks offline while exercising real widgets and workers."""

    def setUp(self):
        """Never consume the operator's automatic-update opt-in during tests."""
        policy = patch("offenders_geoip_ui.read_state", return_value={})
        policy.start()
        self.addCleanup(policy.stop)

    def test_source_and_console_target_launch_dashboard(self):
        """Both launch paths resolve the split modules and run the dashboard."""
        with patch("textual.app.App.run") as run:
            offenders.main([])
            run.assert_called_once_with()
        with patch("textual.app.App.run") as run, patch("sys.argv", ["offenders.py"]), \
             self.assertRaises(SystemExit) as exit_status:
            runpy.run_path(str(Path(offenders.__file__)), run_name="__main__")
        run.assert_called_once_with()
        self.assertEqual(exit_status.exception.code, 0)

    async def test_startup_report_and_keyboard_navigation(self):
        """Mount the dashboard, render a worker result, toggle mode, and quit."""
        report = Report(
            generated_at=dt.datetime(2026, 9, 27, 12),
            period="7d",
            window_start=None,
            events=[BanEvent(dt.datetime(2026, 9, 27, 12), "sshd", "8.8.8.8", "diagnostic")] * 2,
            top_offenders=[Offender("8.8.8.8", 2, "Unknown", "", "No ASN")],
            jail_statuses=[JailStatus("sshd", 0, 0, 2, 2, ("8.8.8.8",))],
        )
        with patch.object(offenders, "build_report", return_value=report):
            app = offenders.OffendersApp()
            async with app.run_test(size=(120, 40)) as pilot:
                await app.workers.wait_for_complete()
                table = app.query_one("#offenders", DataTable)
                self.assertEqual(table.get_row_at(0)[:2], ["2", "8.8.8.8"])
                self.assertEqual(app.query_one("#bans-per-jail", DataTable).get_row_at(0), ["sshd", "2"])
                self.assertEqual(
                    app.query_one("#last-bans", DataTable).get_row_at(0),
                    ["2026-09-27", "12:00:00", "sshd", "8.8.8.8"],
                )
                table.focus()
                await pilot.press("t")
                self.assertEqual(table.cursor_type, "cell")
                await pilot.press("?")
                self.assertIsInstance(app.screen, HelpScreen)
                self.assertIn("Current screen: Dashboard", app.screen.context)
                self.assertIn("Version:", str(app.screen.query_one("#help-project", Static).content))
                await pilot.press("q", "q")
