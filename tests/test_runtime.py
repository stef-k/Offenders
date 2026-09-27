"""Exercise dashboard startup against the supported Textual dependency."""

import datetime as dt
import unittest
from unittest.mock import patch

from textual.widgets import DataTable

import offenders


class RuntimeTests(unittest.IsolatedAsyncioTestCase):
    """Keep runtime checks offline while exercising real widgets and workers."""

    async def test_startup_report_and_keyboard_navigation(self):
        """Mount the dashboard, render a worker result, toggle mode, and quit."""
        report = offenders.Report(
            generated_at=dt.datetime(2026, 9, 27, 12),
            cutoff_date=None,
            total_bans=2,
            ban_lines=[],
            top_offenders=[offenders.Offender("8.8.8.8", 2, "Unknown", "", "No ASN")],
            jail_statuses=[offenders.JailStatus("sshd", 0, 0, 2, 2, ("8.8.8.8",))],
            last_10_bans=["2026-09-27 12:00:00 [sshd] Ban 8.8.8.8"],
        )
        with patch.object(offenders, "build_report", return_value=report):
            app = offenders.OffendersApp()
            async with app.run_test(size=(120, 40)) as pilot:
                await app.workers.wait_for_complete()
                table = app.query_one("#offenders", DataTable)
                self.assertEqual(table.get_row_at(0)[:2], ["2", "8.8.8.8"])
                self.assertEqual(app.query_one("#bans-per-jail", DataTable).get_row_at(0), ["sshd", "2"])
                self.assertEqual(app.query_one("#last-bans", DataTable).get_row_at(0)[-1], "8.8.8.8")
                table.focus()
                await pilot.press("t")
                self.assertEqual(table.cursor_type, "cell")
                await pilot.press("q")
