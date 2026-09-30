"""Real Textual action routing, native footer visibility and focus contracts."""
from dataclasses import replace
from pathlib import Path
import unittest
from unittest.mock import patch

from textual.command import CommandPalette
from textual.containers import VerticalScroll
from textual.widgets import DataTable, Footer, Input

from offenders import OffendersApp
from offenders_enforcement_ui import EnforcementScreen
from offenders_export_ui import ExportScreen
from offenders_help import HelpScreen
from offenders_ip_ui import CommandOutputModal, IPInspectorScreen
from offenders_jail_ui import JailDetailScreen
from offenders_recommendations_ui import RecommendationsScreen
from offenders_validation_ui import ValidationScreen
from test_enforcement_ui import RESULT
from test_refresh import report
from test_validation import inventory


def visible_actions(screen):
    """Read the same native binding authority used by Textual's Footer."""
    return {entry.binding.action for entry in screen.active_bindings.values()
            if entry.binding.show}


class ContextualActionTests(unittest.IsolatedAsyncioTestCase):
    """Keep acquisitions offline while exercising actual screens and keyboard dispatch."""

    def setUp(self):
        """Replace only external/startup work, retaining native action resolution."""
        for target, value in (("offenders.build_report", report()),
                              ("offenders_geoip_ui.read_state", {}),
                              ("offenders_enforcement_ui.check_enforcement", RESULT),
                              ("offenders_recommendations_ui.run_analysis", inventory()),
                              ("offenders_ip_ui.lookup_output", "bounded output")):
            guard = patch(target, return_value=value)
            guard.start()
            self.addCleanup(guard.stop)

    async def test_dashboard_and_investigation_actions(self):
        """Detail views keep report actions and local keys without dashboard navigation."""
        app = OffendersApp()
        async with app.run_test(size=(120, 40)) as pilot:
            await app.workers.wait_for_complete()
            self.assertTrue({"quit", "refresh", "period", "filter", "view", "coverage",
                             "enforcement", "export", "geoip", "registration", "rdns",
                             "copy_selection", "toggle_cursor", "app.help"} <= visible_actions(app.screen))
            await pilot.press("f")
            self.assertIsInstance(app.focused, Input)
            await pilot.press("escape")
            for screen in (JailDetailScreen("sshd", app._last_report, app._push_ip),
                           IPInspectorScreen("8.8.8.8", app._last_report, app._push_jail)):
                with self.subTest(screen=type(screen).__name__):
                    await app.push_screen(screen)
                    await app.workers.wait_for_complete()
                    screen.query_one(DataTable).focus()
                    await pilot.pause()
                    actions = visible_actions(screen)
                    self.assertTrue({"dismiss", "refresh", "period", "app.help",
                                     "copy_selection", "toggle_cursor"} <= actions)
                    self.assertFalse({"quit", "filter", "view", "coverage", "enforcement",
                                      "export", "geoip"} & actions)
                    footer_actions = {getattr(key, "action", "") for key in screen.query_one(Footer).children}
                    self.assertTrue({"refresh", "period", "dismiss", "app.help"} <= footer_actions)
                    self.assertNotIn("geoip", footer_actions)
                    if isinstance(screen, JailDetailScreen):
                        self.assertIn("expand_history", actions)
                        self.assertFalse({"registration", "rdns"} & actions)
                    else:
                        self.assertTrue({"registration", "rdns"} <= actions)
                        self.assertFalse(app.check_action("registration", ()))
                    with patch.object(app, "push_screen") as push:
                        await pilot.press("g", "a", "n", "f")
                        app.action_geoip()
                        app.action_registration()
                        push.assert_not_called()
                    refreshed = replace(report(3), period=app._active_period)
                    with patch("offenders.build_report", return_value=refreshed) as build:
                        await pilot.press("r")
                        await app.workers.wait_for_complete()
                        build.assert_called_once_with(period=refreshed.period)
                        self.assertIs(screen.report, refreshed)
                    changed = replace(report(4), period="30d" if app._active_period == "7d" else "all")
                    with patch("offenders.build_report", return_value=changed) as build:
                        await pilot.press("p")
                        await app.workers.wait_for_complete()
                        build.assert_called_once_with(period=changed.period)
                        self.assertIs(screen.report, changed)
                    await pilot.press("q")
                    self.assertIs(app.screen, app.default_screen)

    async def test_focus_controls_native_footer_and_selection_safety(self):
        """Copy requires a real row; cursor toggling only requires table focus."""
        app = OffendersApp()
        async with app.run_test() as pilot:
            await app.workers.wait_for_complete()
            table = app.query_one("#offenders", DataTable)
            with patch.object(app, "_copy_text") as copy:
                await pilot.press("c", "t", "x")
                self.assertEqual(copy.call_count, 2)
                self.assertEqual(copy.call_args.args, (str(table.get_cell_at(table.cursor_coordinate)),))
                copy.reset_mock()
                await pilot.press("f")
                await pilot.pause()
                self.assertFalse({"copy_selection", "toggle_cursor"} & visible_actions(app.screen))
                footer = app.screen.query_one(Footer)
                self.assertFalse(any(getattr(key, "action", "") in ("copy_selection", "toggle_cursor")
                                     for key in footer.children))
                self.assertFalse(await app.run_action("app.copy_selection"))
                self.assertFalse(await app.run_action("app.toggle_cursor"))
                await pilot.press("escape")
                empty = replace(app._last_report, top_offenders=[], events=[], jail_statuses=[])
                app._apply_report(empty)
                await pilot.pause()
                self.assertNotIn("copy_selection", visible_actions(app.screen))
                self.assertNotIn("copy_selection", {getattr(key, "action", "") for key in footer.children})
                self.assertIn("toggle_cursor", visible_actions(app.screen))
                await pilot.press("c")
                copy.assert_not_called()
            jail = JailDetailScreen("sshd", report(), app._push_ip)
            await app.push_screen(jail)
            table = jail.query_one(DataTable)
            table.focus()
            await pilot.pause()
            self.assertIn("copy_selection", {getattr(key, "action", "") for key in jail.query_one(Footer).children})
            jail.update_report(empty)
            await pilot.pause()
            self.assertNotIn("copy_selection", {getattr(key, "action", "") for key in jail.query_one(Footer).children})
            self.assertIn("toggle_cursor", visible_actions(jail))
            with patch.object(app, "_copy_text") as copy:
                await pilot.press("c", "t", "t")
                copy.assert_not_called()
                self.assertEqual(table.cursor_type, "row")

    async def test_analysis_contexts_preserve_local_actions(self):
        """Coverage owns its period; Enforcement owns Recheck; validation stays isolated."""
        app = OffendersApp()
        inv = inventory()
        async with app.run_test() as pilot:
            await app.workers.wait_for_complete()
            cases = ((RecommendationsScreen(), {"coverage_period", "validate", "close"}),
                     (EnforcementScreen(), {"recheck", "close"}),
                     (ValidationScreen(inv, inv.findings[0]), {"validate", "close"}))
            for screen, local in cases:
                with self.subTest(screen=type(screen).__name__):
                    await app.push_screen(screen)
                    await app.workers.wait_for_complete()
                    await pilot.pause()
                    actions = visible_actions(screen)
                    self.assertTrue(local | {"app.help"} <= actions)
                    self.assertFalse({"refresh", "period", "filter", "view", "coverage", "enforcement",
                                      "export", "geoip", "registration", "rdns", "quit"} & actions)
                    self.assertTrue(any(action.endswith("copy_selection") for action in actions))
                    with patch.object(app, "push_screen") as push, patch.object(app, "refresh_report") as refresh:
                        await pilot.press("a", "g", "n")
                        self.assertFalse(await app.run_action("app.refresh"))
                        self.assertFalse(await app.run_action("app.period"))
                        push.assert_not_called()
                        refresh.assert_not_called()
                    if isinstance(screen, RecommendationsScreen):
                        screen.query_one("#coverage-scroll", VerticalScroll).focus()
                        await pilot.pause()
                        self.assertNotIn("app.toggle_cursor", visible_actions(screen))
                    await pilot.press("q")

    async def test_utility_copy_overrides_and_help_isolation(self):
        """Local conditional c owns utility screens, and Help has only Close."""
        app = OffendersApp()
        async with app.run_test() as pilot:
            await app.workers.wait_for_complete()
            export = ExportScreen(app._last_report)
            await app.push_screen(export)
            await pilot.pause()
            self.assertEqual(visible_actions(export), {"export", "close", "app.help"})
            with patch.object(app, "refresh_report") as refresh:
                await pilot.press("r", "p", "g")
                refresh.assert_not_called()
                self.assertIs(app.screen, export)
            export._complete(Path("/tmp/owned-export"), None)
            await pilot.pause()
            self.assertIn("copy_path", visible_actions(export))
            self.assertNotIn("copy_selection", visible_actions(export))
            with patch.object(app, "copy_to_clipboard") as copy:
                await pilot.press("c", "x")
                copy.assert_called_once_with("/tmp/owned-export")
            await pilot.press("q")
            output = CommandOutputModal("8.8.8.8", "rdns")
            with patch.object(output, "_run"):
                await app.push_screen(output)
                self.assertEqual(visible_actions(output), {"dismiss", "app.help"})
                output._render_output("bounded output")
                self.assertEqual(visible_actions(output), {"dismiss", "copy_output", "app.help"})
                with patch.object(app, "copy_to_clipboard") as copy:
                    await pilot.press("c")
                    copy.assert_called_once_with("bounded output")
            await pilot.press("?", "?")
            self.assertIsInstance(app.screen, HelpScreen)
            self.assertEqual(visible_actions(app.screen), {"dismiss"})

    async def test_native_palette_cannot_dispatch_dashboard_action_from_detail(self):
        """Framework palette stays native and offers no custom Offenders commands."""
        app = OffendersApp()
        async with app.run_test() as pilot:
            await app.workers.wait_for_complete()
            await app.push_screen(JailDetailScreen("sshd", app._last_report, app._push_ip))
            source = app.screen
            self.assertNotIn("GeoIP", {command.title for command in app.get_system_commands(source)})
            await pilot.press("ctrl+p")
            self.assertIsInstance(app.screen, CommandPalette)
            with patch.object(app, "push_screen") as push:
                self.assertFalse(await app.run_action("app.geoip"))
                push.assert_not_called()
            await pilot.press("escape")
            self.assertIs(app.screen, source)
