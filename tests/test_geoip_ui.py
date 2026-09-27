"""Behavioral GeoIP presentation and real Textual background-action checks."""
import asyncio
from dataclasses import replace
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import offenders
import offenders_geoip_ui as ui
import offenders_geoip_update as updater
from offenders_geoip import CandidateHealth, DatabaseHealth
from test_refresh import report


def healthy(source="app-managed", age=0):
    """Representative source snapshot, independent of host databases."""
    item = CandidateHealth(source, "/data/db.mmdb", active=True, exists=True,
                           readable=True, metadata_valid=True, reader_available=True,
                           state="healthy", mtime_ns=int((time.time() - age) * 1e9))
    return DatabaseHealth((item,), source, source == "legacy-system")


class PresentationTests(unittest.TestCase):
    def test_independent_health_staleness_and_source_guidance(self):
        """Global warnings depend on source health, never on unmapped rows."""
        good, missing = healthy(), DatabaseHealth(())
        for country, asn, expected in (
            (good, good, ""), (healthy("legacy-system"), good, ""),
            (missing, good, "Country unavailable"),
            (good, missing, "Asn unavailable"),
            (missing, missing, "Country unavailable; Asn unavailable"),
            (healthy(age=63 * 86400), good, "Country stale (usable)"),
        ):
            with self.subTest(expected=expected):
                line = ui.status_line({"country": country, "asn": asn})
                self.assertIn(expected, line)
                if not expected:
                    self.assertEqual(line, "")
        for value, label in ((good, "app-managed"),
                             (healthy("legacy-system"), "legacy fallback"),
                             (missing, "none")):
            text = str(ui.diagnostics({"country": value}, Path("/data"), {}, ""))
            self.assertIn(f"active source: {label}", text)
            self.assertIn("Automatic updates: off", text)
            self.assertIn("Update now", text)


class ActionsTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        """Keep policy writes and all background work away from real data/network."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "geoip"
        self.health = {"country": healthy(), "asn": healthy()}
        self.report = replace(report(), geoip_health=self.health)
        for target, kwargs in (
            ("offenders_geoip_ui.resolve_data_root", {"return_value": self.root}),
            ("offenders_geoip_ui.geoip.refresh", {"return_value": self.health}),
            ("offenders.build_report", {"return_value": self.report}),
            ("urllib.request.OpenerDirector.open", {"side_effect": AssertionError("network")}),
        ):
            patcher = patch(target, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)

    async def test_missing_data_policy_and_degraded_report_are_independent(self):
        """First launch never fetches; toggling persists; report failure keeps warning."""
        missing = {"country": DatabaseHealth(()), "asn": healthy()}
        with patch.object(ui.geoip, "refresh", return_value=missing), \
             patch.object(offenders, "build_report", return_value=replace(self.report, geoip_health=missing)), \
             patch.object(ui, "update") as update:
            app = offenders.OffendersApp()
            async with app.run_test() as pilot:
                await app.workers.wait_for_complete()
                self.assertFalse(self.root.exists())
                await pilot.press("g")
                await pilot.pause()
                self.assertIn("Update now", str(app.screen.query_one("#geoip-details").content))
                for enabled in (True, False):
                    await pilot.press("a")
                    await app.workers.wait_for_complete()
                    self.assertEqual(updater.read_state(self.root)["auto"], enabled)
                update.assert_not_called()
                await pilot.press("escape")
                with patch.object(offenders, "build_report", side_effect=RuntimeError("offline")):
                    app.refresh_report()
                    await app.workers.wait_for_complete()
                self.assertIn("Degraded", str(app.query_one("#summary").content))
                self.assertIn("Country unavailable", str(app.geoip_status.content))

    async def test_manual_background_activation_duplicate_and_failure(self):
        """Real lock rejects overlap; successful activation refreshes; failure keeps data."""
        entered, release = threading.Event(), threading.Event()
        ui_thread = threading.get_ident()

        def activate(root, *, automatic):
            self.assertFalse(automatic)
            self.assertNotEqual(threading.get_ident(), ui_thread)
            with updater.writer_lock(root):
                entered.set()
                if not release.wait(5):
                    raise AssertionError("update not released")
            return "2026-09"

        with patch.object(ui, "update", side_effect=activate):
            app = offenders.OffendersApp()
            async with app.run_test() as pilot:
                await app.workers.wait_for_complete()
                await pilot.press("g")
                try:
                    await pilot.press("u")
                    self.assertTrue(await asyncio.to_thread(entered.wait, 3))
                    duplicate = app.geoip_status.update_now()
                    await duplicate.wait()
                    self.assertIn("already running", app.geoip_status.feedback)
                finally:
                    release.set()
                await app.workers.wait_for_complete()
                self.assertIn("Activated 2026-09", app.geoip_status.feedback)
                self.assertEqual(str(app.geoip_status.content), "")
                # Unknown/unmapped offender rows do not create a health warning.
                self.assertIn("Unknown", app.query_one("#offenders").get_row_at(0))
                with patch.object(ui, "update", side_effect=updater.UpdateError("[red]offline\n" * 100)):
                    await pilot.press("u")
                    await app.workers.wait_for_complete()
                self.assertEqual(app.geoip_status.health, self.health)
                self.assertEqual(str(app.geoip_status.content), "")
                self.assertLessEqual(len(app.geoip_status.feedback), 240)
                self.assertNotIn("\n", app.geoip_status.feedback)

    async def test_automatic_mount_only_activation_noop_and_failure(self):
        """One mount check delegates due policy; only activation requests refresh."""
        updater.set_auto(True, self.root)
        for result, builds in ((None, 1), ("2026-09", 2), (updater.UpdateError("offline"), 1)):
            with self.subTest(result=result):
                started, release = threading.Event(), threading.Event()

                def automatic(root, *, automatic):
                    self.assertTrue(automatic)
                    started.set()
                    if not release.wait(5):
                        raise AssertionError("automatic check not released")
                    if isinstance(result, Exception):
                        raise result
                    return result

                with patch.object(ui, "update", side_effect=automatic) as update, \
                     patch.object(offenders, "build_report", return_value=self.report) as build:
                    app = offenders.OffendersApp()
                    async with app.run_test():
                        try:
                            self.assertTrue(await asyncio.to_thread(started.wait, 3))
                            await app._refresh_worker.wait()
                        finally:
                            release.set()
                        await app.workers.wait_for_complete()
                        self.assertEqual(build.call_count, builds)
                        self.assertEqual(str(app.geoip_status.content), "")
                        app.refresh_report()  # The actual timer callback.
                        await app.workers.wait_for_complete()
                        update.assert_called_once_with(self.root, automatic=True)
