"""Copy actions require the currently displayed result and its live owner."""
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from offenders import OffendersApp
from offenders_candidate import generate_candidate
from offenders_candidate_ui import CustomCandidateScreen, copy_text
from offenders_export_ui import ExportScreen
from offenders_ip_ui import CommandOutputModal
from test_candidate import matched, web_inventory
from test_refresh import report


class ResultStateTests(unittest.IsolatedAsyncioTestCase):
    """Test result delivery seams without network, disk writes or clipboard I/O."""

    def setUp(self):
        """Supply a committed offline report and disable automatic updates."""
        for name, value in (("offenders.build_report", report()),
                            ("offenders_geoip_ui.read_state", {})):
            mock = patch(name, return_value=value)
            mock.start()
            self.addCleanup(mock.stop)

    async def test_export_copy_restart_failure_and_late_delivery(self):
        """A rerun invalidates the previous path before the worker can finish."""
        app = OffendersApp()
        async with app.run_test():
            await app.workers.wait_for_complete()
            await app.push_screen(ExportScreen(app._last_report))
            screen = app.screen
            path = Path("/tmp/exact successful bundle")
            with patch.object(screen, "_export"), patch.object(app, "copy_to_clipboard") as copy:
                screen.action_copy_path()
                copy.assert_not_called()
                screen.action_export()
                screen._complete(path, None)
                screen.action_copy_path()
                copy.assert_called_once_with(str(path))
                copy.reset_mock()
                screen.action_export()
                self.assertIsNone(screen.path)
                screen.action_copy_path()
                screen._complete(path, None, SimpleNamespace(is_cancelled=True))
                screen.action_copy_path()
                self.assertIsNone(screen.path)
                screen._complete(None, "Export failed")
                screen.action_copy_path()
                copy.assert_not_called()
                screen.action_export()
                screen.action_close()
                screen._complete(path, None)
                screen.action_copy_path()
                self.assertIsNone(screen.path)
                self.assertFalse(screen.check_action("copy_path", ()))
                copy.assert_not_called()

    async def test_candidate_copy_restart_withheld_failure_and_close(self):
        """Only the current reviewable candidate exposes its exact validated text."""
        inv = web_inventory()
        with patch("offenders_candidate.validate_custom", side_effect=matched):
            result = generate_candidate(inv, inv.findings[0])
        app = OffendersApp()
        async with app.run_test():
            await app.workers.wait_for_complete()
            await app.push_screen(CustomCandidateScreen(inv, inv.findings[0]))
            screen = app.screen
            with patch.object(screen, "_generate"), patch.object(app, "copy_to_clipboard") as copy:
                screen.action_copy_candidate()
                copy.assert_not_called()
                screen.action_generate()
                screen._complete(result, None)
                screen.action_copy_candidate()
                copy.assert_called_once_with(copy_text(result))
                copy.reset_mock()
                screen.action_generate()
                self.assertIsNone(screen.result)
                screen.action_copy_candidate()
                screen._complete(result, None, SimpleNamespace(is_cancelled=True))
                self.assertIsNone(screen.result)
                screen._complete(replace(result, state="withheld"), None)
                screen.action_copy_candidate()
                screen.action_generate()
                screen._complete(None, "Generation failed")
                screen.action_copy_candidate()
                copy.assert_not_called()
                screen.action_generate()
                screen.action_close()
                screen._complete(result, None)
                screen.action_copy_candidate()
                self.assertFalse(screen.check_action("copy_candidate", ()))
                copy.assert_not_called()

    async def test_lookup_copy_empty_cancelled_and_dismissed_output(self):
        """Both tools copy rendered output only, never a queued late completion."""
        with patch.object(CommandOutputModal, "_run"):
            app = OffendersApp()
            async with app.run_test():
                await app.workers.wait_for_complete()
                for tool in ("registration", "rdns"):
                    await app.push_screen(CommandOutputModal("8.8.8.8", tool))
                    screen = app.screen
                    with patch.object(app, "copy_to_clipboard") as copy:
                        screen.action_copy_output()
                        screen._render_output("")
                        screen.action_copy_output()
                        screen._render_output("cancelled", SimpleNamespace(is_cancelled=True))
                        screen.action_copy_output()
                        copy.assert_not_called()
                        screen._render_output("[literal] bounded output")
                        screen.action_copy_output()
                        copy.assert_called_once_with("[literal] bounded output")
                        copy.reset_mock()
                        await app.pop_screen()
                        screen._render_output("late replacement")
                        screen.action_copy_output()
                        self.assertFalse(screen.check_action("copy_output", ()))
                        self.assertEqual(screen._output_text, "[literal] bounded output")
                        copy.assert_not_called()
