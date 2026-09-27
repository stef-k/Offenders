"""Deterministic refresh contracts through real Textual workers and widgets."""

import asyncio
import datetime as dt
import threading
import unittest
from unittest.mock import patch

from textual.widgets import DataTable, Static

import offenders
from offenders_fail2ban import (
    CommandFailure, CommandResult, Fail2BanCommandError, Fail2BanParseError, JailStatus,
)
from offenders_report import Offender, Report


def report(count=2):
    """Build distinctive trustworthy data without host collection."""
    return Report(
        generated_at=dt.datetime(2026, 9, 27, 12, count),
        cutoff_date=None, total_bans=count, ban_lines=[],
        top_offenders=[Offender("8.8.8.8", count, "Unknown", "", "No ASN")],
        jail_statuses=[JailStatus("sshd", 0, 0, count, count, ("8.8.8.8",))],
        last_10_bans=["2026-09-27 12:00:00 [sshd] Ban 8.8.8.8"],
    )


def rendered(app):
    """Snapshot all displayed data, including the last-success subtitle."""
    return (
        tuple(tuple(tuple(table.get_row_at(i)) for i in range(table.row_count))
              for table in app.query(DataTable)),
        str(app.query_one("#jails-line", Static).content),
        app.sub_title,
    )


class RefreshTests(unittest.IsolatedAsyncioTestCase):
    """Use explicit thread barriers instead of sleep-based overlap assertions."""

    def setUp(self):
        """Never consume the operator's automatic-update opt-in during tests."""
        policy = patch("offenders_geoip_ui.read_state", return_value={})
        policy.start()
        self.addCleanup(policy.stop)

    async def wait_started(self, event):
        """Bound deadlock failures without using time as synchronization."""
        self.assertTrue(await asyncio.to_thread(event.wait, 3))

    async def test_slow_build_skips_timer_and_manual_then_releases(self):
        """Mount, timer, and keyboard share one build; success permits the next."""
        entered, release = threading.Event(), threading.Event()

        def collect():
            entered.set()
            if not release.wait(3):
                raise AssertionError("test did not release collector")
            return report()

        with patch.object(offenders, "build_report", side_effect=collect) as build:
            app = offenders.OffendersApp()
            async with app.run_test() as pilot:
                try:
                    await self.wait_started(entered)
                    with patch.object(app, "notify") as notify:
                        app.refresh_report()  # Same callback registered with the timer.
                        notify.assert_not_called()
                        await pilot.press("r")
                        notify.assert_called_once_with(
                            "Refresh already in progress", timeout=2.0
                        )
                    self.assertEqual(build.call_count, 1)
                finally:
                    release.set()
                await app.workers.wait_for_complete()
                app.refresh_report()
                await app.workers.wait_for_complete()
                self.assertEqual(build.call_count, 2)

    async def test_failure_retains_tables_and_success_recovers(self):
        """Failure keeps trustworthy data, bounds text, and releases the gate."""
        error = Fail2BanCommandError(
            ["status"], CommandResult(
                None, "", "[red]bad\n" * 100, CommandFailure.TIMEOUT
            ),
        )
        with patch.object(offenders, "build_report", side_effect=[report(), error, report(3)]):
            app = offenders.OffendersApp()
            async with app.run_test():
                await app.workers.wait_for_complete()
                before = rendered(app)
                app.refresh_report()
                await app.workers.wait_for_complete()
                self.assertEqual(rendered(app), before)
                summary = str(app.query_one("#summary").content)
                self.assertIn("Degraded", summary)
                self.assertIn("timeout", summary)
                self.assertIn("Showing last successful refresh 2026-09-27 12:02:00", summary)
                self.assertIn("[red]bad", summary)
                self.assertNotIn("\n", summary)
                self.assertLess(len(summary), 320)
                app.refresh_report()
                await app.workers.wait_for_complete()
                self.assertNotEqual(rendered(app), before)
                self.assertNotIn("Degraded", str(app.query_one("#summary").content))
                self.assertEqual(app.query_one("#offenders", DataTable).get_row_at(0)[0], "3")

    async def test_initial_failure_is_unavailable_then_zero_is_authoritative(self):
        """No initial failure fabricates counts; a real empty report is valid."""
        empty = Report(dt.datetime(2026, 9, 27), None, 0, [], [], [], [])
        with patch.object(offenders, "build_report", side_effect=[
            Fail2BanParseError("missing jail field"), empty,
        ]):
            app = offenders.OffendersApp()
            async with app.run_test():
                await app.workers.wait_for_complete()
                summary = str(app.query_one("#summary").content)
                self.assertIn("Unavailable: no successful refresh", summary)
                self.assertIn("parse-failure: missing jail field", summary)
                self.assertTrue(all(table.row_count == 0 for table in app.query(DataTable)))
                app.refresh_report()
                await app.workers.wait_for_complete()
                self.assertIn("bans=0", str(app.query_one("#summary").content))
                self.assertNotIn("Degraded", str(app.query_one("#summary").content))

    async def test_cancelled_running_thread_stays_gated_and_cannot_apply(self):
        """Cancellation cannot overlap builders or apply a cancelled result."""
        entered, release = threading.Event(), threading.Event()

        def collect():
            entered.set()
            if not release.wait(3):
                raise AssertionError("test did not release collector")
            return report()

        with patch.object(offenders, "build_report", side_effect=collect) as build:
            app = offenders.OffendersApp()
            async with app.run_test() as pilot:
                try:
                    await self.wait_started(entered)
                    app._refresh_worker.cancel()
                    await pilot.pause()
                    app.refresh_report()
                    self.assertEqual(build.call_count, 1)
                finally:
                    release.set()
                # A cancelled Textual task can finish before its Python thread.
                self.assertTrue(await asyncio.to_thread(app._build_lock.acquire, True, 3))
                app._build_lock.release()
                self.assertTrue(all(table.row_count == 0 for table in app.query(DataTable)))
                app.refresh_report()
                await app.workers.wait_for_complete()
                self.assertEqual(build.call_count, 2)
                self.assertEqual(app.query_one("#offenders", DataTable).get_row_at(0)[0], "2")

    async def test_cancellation_before_thread_start_releases_gate(self):
        """Cancelled scheduled work cannot strand a gate acquired at scheduling."""
        with patch.object(offenders, "build_report", return_value=report()) as build:
            app = offenders.OffendersApp()
            async with app.run_test() as pilot:
                await app.workers.wait_for_complete()
                app.refresh_report()
                app._refresh_worker.cancel()
                await pilot.pause()
                app.refresh_report()
                await app.workers.wait_for_complete()
                self.assertEqual(build.call_count, 2)
