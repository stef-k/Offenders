"""Real worker lifecycle and visible app-wide activity, with causal barriers."""
import asyncio
import ast
from dataclasses import replace
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

from textual.screen import Screen
from textual.worker import WorkerFailed

from offenders import OffendersApp
from offenders_activity import ActivityStatus
from offenders_ip_ui import CommandOutputModal
from test_refresh import report, rendered


class ActivityTests(unittest.IsolatedAsyncioTestCase):
    """Exercise the shared manager through product actions and ordinary workers."""

    def setUp(self):
        """Keep tests independent of host collection and automatic-update policy."""
        for target, value in (("offenders.build_report", report()),
                              ("offenders_geoip_ui.read_state", {})):
            mock = patch(target, return_value=value)
            mock.start()
            self.addCleanup(mock.stop)

    def visible(self, app):
        """Read the presenter on the active screen, not coordinator internals."""
        status = app.screen.query_one(ActivityStatus)
        self.assertTrue(status.is_on_screen)
        return str(status.content)

    async def test_refresh_and_period_keep_committed_data_until_success(self):
        """Both keypresses show pending work while last-good tables remain usable."""
        app = OffendersApp()
        async with app.run_test() as pilot:
            await app.workers.wait_for_complete()
            for key, target, label in (("r", "7d", "Refreshing…"), ("p", "30d", "Loading 30d…")):
                started, release = threading.Event(), threading.Event()

                def collect(*, period):
                    self.assertEqual(period, target)
                    started.set()
                    if not release.wait(5):
                        raise AssertionError("collector was not released")
                    return replace(report(3), period=period)

                with self.subTest(key=key), patch("offenders.build_report", side_effect=collect) as build:
                    before = rendered(app)
                    try:
                        await pilot.press(key)
                        self.assertTrue(await asyncio.to_thread(started.wait, 3))
                        self.assertIn(label, self.visible(app))
                        self.assertEqual(rendered(app), before)
                        self.assertEqual(app._active_period, "7d")
                        with patch.object(app, "notify") as notify:
                            await pilot.press("r")
                            notify.assert_called_once_with("Refresh already in progress", timeout=2.0)
                        self.assertEqual(build.call_count, 1)
                    finally:
                        release.set()
                    await app.workers.wait_for_complete()
                    self.assertEqual(self.visible(app), "")
                    self.assertEqual(app._active_period, target)

    async def test_generic_overlap_error_and_cancel_before_start(self):
        """Future plain workers need no labels; one completion cannot clear another."""
        app = OffendersApp()
        async with app.run_test() as pilot:
            await app.workers.wait_for_complete()
            release = asyncio.Event()
            await app.push_screen(Screen())
            await pilot.pause()
            first = app.screen.run_worker(release.wait)
            second = app.run_worker(release.wait)
            self.assertIn("Working… (2 active)", self.visible(app))
            first.cancel()  # Before its coroutine starts.
            await pilot.pause()
            self.assertEqual(self.visible(app), "Working…")

            async def fail():
                raise RuntimeError("bounded test failure")

            failed = app.screen.run_worker(fail(), exit_on_error=False)
            with self.assertRaises(WorkerFailed):
                await failed.wait()
            await pilot.pause()
            self.assertEqual(self.visible(app), "Working…")
            release.set()
            await second.wait()
            await pilot.pause()
            self.assertEqual(self.visible(app), "")
            # Explicitly deferred workers are quiet until started.
            deferred = app.run_worker(release.wait, start=False)
            self.assertEqual(self.visible(app), "")
            app.workers.start_all()
            self.assertEqual(self.visible(app), "Working…")
            await deferred.wait()
            await pilot.pause()
            self.assertEqual(self.visible(app), "")

    async def test_lookup_pending_output_completion_and_dismissal(self):
        """Provider wording is visible before output; dismissal rejects late output."""
        app = OffendersApp()
        async with app.run_test() as pilot:
            await app.workers.wait_for_complete()
            for tool, label, dismiss in (("registration", "Querying RDAP…", False),
                                         ("rdns", "Resolving PTR…", True)):
                started, release, finished = threading.Event(), threading.Event(), threading.Event()

                def lookup(ip, selected):
                    started.set()
                    try:
                        if not release.wait(5):
                            raise AssertionError("lookup was not released")
                        return "bounded answer"
                    finally:
                        finished.set()

                with patch("offenders_ip_ui.lookup_output", side_effect=lookup):
                    modal = CommandOutputModal("8.8.8.8", tool)
                    await app.push_screen(modal)
                    try:
                        self.assertTrue(await asyncio.to_thread(started.wait, 3))
                        await pilot.pause()
                        self.assertIn(label, self.visible(app))
                        self.assertIn(label, "".join(line.text for line in modal.query_one("#cmd-out").lines))
                        if dismiss:
                            await pilot.press("escape")
                            self.assertEqual(self.visible(app), "")
                    finally:
                        release.set()
                    self.assertTrue(await asyncio.to_thread(finished.wait, 3))
                    await app.workers.wait_for_complete()
                    await pilot.pause()
                    self.assertEqual(self.visible(app), "")
                    if dismiss:
                        self.assertEqual(modal._output_text, "")
                    else:
                        self.assertEqual(modal._output_text, "bounded answer")
                        self.assertNotIn(label, "".join(line.text for line in modal.query_one("#cmd-out").lines))
                        await pilot.press("escape")


class AsyncAuditTests(unittest.TestCase):
    """Make bypassing the shared Textual manager an explicit review decision."""

    def test_runtime_work_uses_textual_manager(self):
        """Audit packaged code for worker entry points and unmanaged scheduling."""
        workers = []
        for path in Path(__file__).resolve().parents[1].glob("offenders*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and any(alias.name == "work" for alias in node.names):
                    self.assertEqual(node.module, "textual", str(path))
                if not isinstance(node, ast.Call):
                    continue
                name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
                self.assertNotIn(name, {"create_task", "ensure_future", "Thread", "ThreadPoolExecutor",
                                        "ProcessPoolExecutor", "run_in_executor", "to_thread"}, str(path))
                if name == "work":
                    workers.append(path.name)
        # This is the current audit baseline, not an allowlist for future workers.
        self.assertGreaterEqual(len(workers), 10)
