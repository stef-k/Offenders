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
            await pilot.press("ctrl+p")
            palette = app.screen
            self.assertIsInstance(palette, CommandPalette)
            await pilot.press("?")
            self.assertIs(app.screen, palette)
            self.assertFalse(palette.query(OffendersFooter))
            await pilot.press("escape", "?")
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
