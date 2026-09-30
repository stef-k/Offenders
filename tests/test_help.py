"""Offline contracts for contextual Help, runtime controls and literal metadata."""
import unittest
from unittest.mock import patch

from textual.command import CommandPalette
from textual.containers import VerticalScroll
from textual.widgets import Input, Static

from offenders import OffendersApp
from offenders_activity import OffendersFooter
from offenders_help import HelpScreen
from test_refresh import report


class HelpNavigationTests(unittest.IsolatedAsyncioTestCase):
    """Exercise real keys without allowing automatic host acquisition."""

    def setUp(self):
        """Replace only startup acquisitions; Help must not invoke them again."""
        for target, value in (("offenders.build_report", report()),
                              ("offenders_geoip_ui.read_state", {})):
            guard = patch(target, return_value=value)
            guard.start()
            self.addCleanup(guard.stop)

    async def test_filter_priority_no_recursion_and_exact_return(self):
        """Reserved Help key preserves filter text and focused input on return."""
        app = OffendersApp()
        async with app.run_test() as pilot:
            await app.workers.wait_for_complete()
            dashboard = app.screen
            await pilot.press("f", "s", "s", "h")
            query = app.query_one("#filter", Input)
            self.assertIs(app.focused, query)
            with patch.object(app, "refresh_report") as refresh:
                await pilot.press("?")
                self.assertIsInstance(app.screen, HelpScreen)
                self.assertIn("Current screen: Dashboard", str(app.screen.query_one("#help-context", Static).content))
                help_screen = app.screen
                await pilot.press("?", "r", "p", "e", "a", "g", "w", "d", "v")
                self.assertIs(app.screen, help_screen)
                refresh.assert_not_called()
                await pilot.press("escape")
            self.assertIs(app.screen, dashboard)
            self.assertIs(app.focused, query)
            self.assertEqual(query.value, "ssh")
            await pilot.press("?", "q")
            self.assertIs(app.screen, dashboard)

    async def test_palette_is_native_and_help_scrolls_in_small_terminal(self):
        """Help uses one footer row and leaves framework screen ownership intact."""
        app = OffendersApp()
        async with app.run_test(size=(40, 16)) as pilot:
            await app.workers.wait_for_complete()
            app._help_project_info = "Version: test\nSource: https://example.test/[bold]/" + "long-url/" * 150
            await pilot.press("ctrl+p")
            palette = app.screen
            self.assertIsInstance(palette, CommandPalette)
            await pilot.press("?")
            self.assertIs(app.screen, palette)
            self.assertFalse(palette.query(OffendersFooter))
            await pilot.press("escape", "?")
            self.assertEqual(str(app.screen.query_one("#help-project", Static).content), app._help_project_info)
            self.assertIn("[bold]", app.screen.query_one("#help-project", Static).visual.plain)
            scroll = app.screen.query_one(VerticalScroll)
            self.assertEqual(scroll.scroll_y, 0)
            self.assertEqual(app.screen.query_one(OffendersFooter).region.height, 1)
            await pilot.press("end")
            await pilot.pause()
            self.assertGreater(scroll.scroll_y, 0)
            await pilot.press("home")
            await pilot.pause()
            self.assertEqual(scroll.scroll_y, 0)
            await pilot.press("q")
            self.assertIs(app.screen, app.default_screen)

    async def test_every_product_context_is_local_and_preserves_its_source(self):
        """Mount each real product view, then forbid new work during Help use."""
        from contextlib import ExitStack
        from textual.binding import Binding
        from offenders_candidate_ui import CustomCandidateScreen
        from offenders_export_ui import ExportScreen
        from offenders_geoip_ui import GeoIPScreen
        from offenders_ip_ui import CommandOutputModal, IPInspectorScreen
        from offenders_jail_ui import JailDetailScreen
        from offenders_recommendations_ui import RecommendationsScreen
        from offenders_validation_ui import ValidationScreen
        from test_candidate import web_inventory
        from test_validation import inventory

        inv, custom = inventory(), web_inventory()
        app = OffendersApp()
        with patch("offenders_recommendations_ui.run_analysis", return_value=inv), \
                patch("offenders_ip_ui.lookup_output", return_value="bounded output"):
            async with app.run_test(size=(90, 30)) as pilot:
                await app.workers.wait_for_complete()
                cases = (
                    (JailDetailScreen("sshd", report(), app._push_ip), "Jail detail",
                     ("refresh", "period", "expand_history", "copy_selection", "toggle_cursor", "enter", "dismiss"),
                     "without reacquiring"),
                    (IPInspectorScreen("8.8.8.8", report(), app._push_jail), "IP inspector",
                     ("refresh", "period", "registration", "rdns", "copy_selection", "toggle_cursor", "enter", "dismiss"),
                     "separate network"),
                    (ExportScreen(report()), "Export", ("export", "copy_path", "close"), "captured"),
                    (GeoIPScreen(app.geoip_status), "GeoIP diagnostics",
                     ("update_now", "toggle_auto", "dismiss"), "before activation"),
                    (CommandOutputModal("8.8.8.8", "registration"), "Registration (RDAP)",
                     ("copy_output", "dismiss"), "Neither Registration nor PTR data"),
                    (CommandOutputModal("8.8.8.8", "rdns"), "RDNS (PTR)",
                     ("copy_output", "dismiss"), "Neither Registration nor PTR data"),
                    (RecommendationsScreen(), "Coverage / Recommendations",
                     ("coverage_period", "validate", "app.copy_selection", "app.toggle_cursor", "close"), "do not prove"),
                    (ValidationScreen(inv, inv.findings[0]), "Existing-filter validation",
                     ("validate", "copy_selection", "toggle_cursor", "enter", "close"), "does not enable/reload/change"),
                    (CustomCandidateScreen(custom, custom.findings[0]), "Custom candidate",
                     ("generate", "copy_candidate", "close"), "disabled/copy-only"),
                )
                for screen, name, actions, semantics in cases:
                    with self.subTest(screen=name):
                        await app.push_screen(screen)
                        await app.workers.wait_for_complete()
                        await pilot.pause()
                        focus = screen.focused
                        with ExitStack() as guards:
                            no_worker = guards.enter_context(patch.object(app.workers, "add_worker"))
                            no_metadata = guards.enter_context(patch("offenders_help_content.metadata.metadata"))
                            no_network = guards.enter_context(patch("socket.create_connection"))
                            no_host = guards.enter_context(patch("subprocess.Popen"))
                            await pilot.press("?")
                            self.assertIsInstance(app.screen, HelpScreen)
                            text = str(app.screen.query_one("#help-context", Static).content)
                            self.assertTrue(text.startswith("Current screen: " + name))
                            self.assertIn(semantics, text)
                            rows = [line for line in text.splitlines() if line.startswith("  ")]
                            self.assertEqual(len(rows), len(actions))
                            bindings = tuple(Binding.make_bindings([*screen.BINDINGS, *app.BINDINGS]))
                            for row, action in zip(rows, actions):
                                if action == "enter":
                                    self.assertTrue(row.startswith("  Enter  "))
                                else:
                                    matches = [b for b in bindings if b.action == action]
                                    self.assertTrue(matches)
                                    for binding in matches:
                                        self.assertIn(binding.description, row)
                                        self.assertIn("Esc" if binding.key == "escape" else binding.key, row)
                            if "copy_path" in actions:
                                self.assertIn("after successful export", text)
                            if "copy_candidate" in actions:
                                self.assertIn("reviewable validated result", text)
                            if "copy_output" in actions:
                                self.assertIn("when result output exists", text)
                            await pilot.press("?", "end", "escape")
                            self.assertIs(app.screen, screen)
                            self.assertIs(screen.focused, focus)
                            no_worker.assert_not_called()
                            no_metadata.assert_not_called()
                            no_network.assert_not_called()
                            no_host.assert_not_called()
                        await pilot.press("q")

    async def test_enter_supplements_follow_real_table_selection(self):
        """Advertised Enter routes dashboard → jail → IP → jail and validation."""
        from textual.widgets import DataTable
        from offenders_ip_ui import IPInspectorScreen
        from offenders_jail_ui import JailDetailScreen
        from offenders_validation_ui import ValidationScreen
        from test_validation import inventory

        app = OffendersApp()
        async with app.run_test(size=(100, 40)) as pilot:
            await app.workers.wait_for_complete()
            for table_id, kind in (("#offenders", IPInspectorScreen), ("#last-bans", IPInspectorScreen),
                                   ("#bans-per-jail", JailDetailScreen)):
                app.screen.query_one(table_id, DataTable).focus()
                await pilot.press("?")
                self.assertIn("Enter  Open selected real IP or active jail", app.screen.context)
                await pilot.press("q", "enter")
                self.assertIsInstance(app.screen, kind)
                await app.workers.wait_for_complete()
                await pilot.press("q")
            app.screen.query_one("#bans-per-jail", DataTable).focus()
            await pilot.press("enter", "e")
            jail = app.screen
            history = jail.query_one("#jail-history", DataTable)
            history.focus()
            await pilot.press("?")
            self.assertIn("Enter  Open selected historical IP", app.screen.context)
            await pilot.press("q", "enter")
            self.assertIsInstance(app.screen, IPInspectorScreen)
            self.assertEqual(app.screen.ip, "8.8.8.8")
            await app.workers.wait_for_complete()
            app.screen.query_one("#ip-jails", DataTable).focus()
            await pilot.press("?")
            self.assertIn("Enter  Open selected listed jail", app.screen.context)
            await pilot.press("escape", "enter")
            self.assertIsInstance(app.screen, JailDetailScreen)
            self.assertEqual(app.screen.jail, "sshd")
            inv = inventory()
            validation = ValidationScreen(inv, inv.findings[0])
            await app.push_screen(validation)
            with patch.object(validation, "_validate") as validate:
                await pilot.press("?")
                self.assertIn("Enter  Validate selected target", app.screen.context)
                await pilot.press("q", "enter")
                validate.assert_called_once_with(validation.targets[0])

    async def test_underlying_scroll_selection_and_background_activity_survive(self):
        """Help leaves existing detail state and accepted worker lifetime alone."""
        import asyncio
        from offenders_activity import ActivityStatus
        from offenders_jail_ui import JailDetailScreen
        from textual.widgets import DataTable

        app = OffendersApp()
        async with app.run_test(size=(60, 20)) as pilot:
            await app.workers.wait_for_complete()
            jail = JailDetailScreen("sshd", report(55), app._push_ip)
            await app.push_screen(jail)
            await pilot.press("e")
            table = jail.query_one(DataTable)
            table.focus()
            await pilot.press("end")
            await pilot.pause()
            before = (table.cursor_coordinate, table.scroll_y, jail.history_level, jail.report)
            release = asyncio.Event()
            worker = app.run_worker(release.wait, name="activity:Refreshing…")
            try:
                await pilot.press("?")
                self.assertIn("Refreshing…", str(app.screen.query_one(ActivityStatus).content))
                await pilot.press("end", "q")
                self.assertIs(app.screen, jail)
                self.assertEqual((table.cursor_coordinate, table.scroll_y, jail.history_level, jail.report), before)
                self.assertIs(app.focused, table)
                self.assertFalse(worker.is_cancelled)
            finally:
                release.set()
                await worker.wait()


class HelpContentTests(unittest.TestCase):
    """Small semantic assertions avoid frozen prose snapshots."""

    def test_runtime_binding_changes_are_reflected_and_copy_stays_conditional(self):
        """A changed runtime key/description needs no parallel Help edit."""
        from offenders_export_ui import ExportScreen
        from offenders_help import CONTEXTS, context_text
        text = context_text(CONTEXTS[ExportScreen], [
            ("z", "export", "Write bundle"), ("k", "copy_path", "Retain path"),
            ("escape", "close", "Return"), ("q", "close", "Return"),
        ])
        self.assertIn("z  Write bundle", text)
        self.assertIn("k  Retain path (available after successful export", text)
        self.assertIn("Esc/q  Return", text)

    def test_inherited_report_controls_and_local_keys_use_runtime_authority(self):
        """Inherited Help labels follow app bindings while local keys retain ownership."""
        from offenders_help import CONTEXTS, context_text
        from offenders_ip_ui import IPInspectorScreen
        text = context_text(CONTEXTS[IPInspectorScreen], IPInspectorScreen.BINDINGS, [
            ("z", "refresh", "Reload report"), ("s", "period", "History window"),
            ("w", "registration", "Dashboard registration"),
            ("d", "rdns", "Dashboard PTR"),
            ("c", "copy_selection", "Copy"), ("x", "copy_selection", "Copy"),
            ("t", "toggle_cursor", "Row/Cell"),
        ])
        self.assertIn("z  Reload report", text)
        self.assertIn("s  History window", text)
        self.assertIn("w  Registration", text)
        self.assertNotIn("Dashboard registration", text)
        self.assertNotIn("Dashboard PTR", text)
        self.assertIn("c/x  Copy (when a table is focused with a valid selection)", text)
        self.assertIn("Enter  Open selected listed jail", text)

    def test_complete_guide_and_period_authority(self):
        """Guide covers shipped features, CLI commands and key distinctions."""
        from offenders_help_content import product_guide
        from offenders_report import DEFAULT_PERIOD, PERIODS
        guide = product_guide(OffendersApp.BINDINGS)
        for fragment in ("Dashboard", "Investigation", "Export", "GeoIP", "Registration and RDNS",
                         "Coverage and validation", "report.csv", "top-offenders.csv", "jail-status.csv",
                         "ban-events.csv", "~/offenders-exports/", "captured when Export was opened",
                         "no new report acquisition", "Unmapped", "Unavailable != zero/empty",
                         "non-global Registration skips network", "disabled and copy-only",
                         "offenders --help", "offenders --version", "never bans/unbans",
                         "last successful snapshot", "default: " + DEFAULT_PERIOD, ", ".join(PERIODS)):
            self.assertIn(fragment, guide)
        command_line = guide.split("Command line\n", 1)[1].split("\n\n", 1)[0]
        self.assertEqual(len(command_line.splitlines()), 1)
        self.assertNotIn("offenders export", command_line)
        self.assertNotIn("offenders geoip", command_line)

    def test_metadata_values_and_failure_fallback_are_bounded_and_local(self):
        """Use installed metadata literally, with no assumed release number."""
        from email.message import Message
        from importlib.metadata import PackageNotFoundError
        from offenders_help_content import PROJECT_URLS, project_information
        package = Message()
        package["Version"] = "9.8.7+test"
        for label in PROJECT_URLS:
            package["Project-URL"] = f"{label}, https://example.test/[bold]/{label}"
        with patch("offenders_help_content.metadata.metadata", return_value=package), \
                patch("offenders_help_content.metadata.version", return_value=package["Version"]):
            text = project_information()
        self.assertIn("Version: 9.8.7+test", text)
        for label in PROJECT_URLS:
            self.assertIn(f"{label}: https://example.test/[bold]/{label}", text)
        for error in (PackageNotFoundError("offenders"), OSError("unreadable"), ValueError("invalid")):
            with self.subTest(error=error), \
                    patch("offenders_help_content.metadata.metadata", side_effect=error), \
                    patch("offenders_help_content.metadata.version", side_effect=error):
                text = project_information()
                self.assertIn("Unavailable (source development)", text)
                for url in PROJECT_URLS.values():
                    self.assertIn(url, text)
