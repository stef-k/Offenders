"""Invalid selections must never become a different row's action."""
from dataclasses import replace
import unittest
from unittest.mock import patch, PropertyMock

from textual.coordinate import Coordinate
from textual.widgets import DataTable, Static

from offenders import OffendersApp
from offenders_recommendations_ui import RecommendationsScreen
from offenders_validation_ui import ValidationScreen
from test_refresh import report
from test_validation import inventory


class SelectionTests(unittest.IsolatedAsyncioTestCase):
    """Exercise handlers against mounted tables, including queued stale events."""

    def setUp(self):
        """Keep all acquisition offline and deterministic."""
        for name, value in (("offenders.build_report", report()),
                            ("offenders_geoip_ui.read_state", {})):
            mock = patch(name, return_value=value)
            mock.start()
            self.addCleanup(mock.stop)

    async def test_coverage_empty_highlight_and_invalid_validation(self):
        """Reproduce the production event before and after population."""
        inv = inventory(disabled=(("first", "sshd"),))
        with patch.object(RecommendationsScreen, "_analyze"):
            app = OffendersApp()
            async with app.run_test() as pilot:
                await app.workers.wait_for_complete()
                await app.push_screen(RecommendationsScreen())
                screen = app.screen
                table = screen.query_one(DataTable)
                table.focus()
                screen.highlight_finding(DataTable.RowHighlighted(table, -1, None))
                with patch.object(app, "push_screen") as push:
                    screen.action_validate()
                    push.assert_not_called()
                screen._complete(inv, None)
                self.assertTrue(str(screen.query_one("#coverage-detail", Static).content))
                key = next(iter(table.rows))
                with patch.object(DataTable, "cursor_coordinate", new_callable=PropertyMock,
                                  return_value=Coordinate(-1, 0)), patch.object(app, "push_screen") as push:
                    screen.action_validate()
                    push.assert_not_called()
                table.clear()
                screen.highlight_finding(DataTable.RowHighlighted(table, 0, key))
                with patch.object(app, "push_screen") as push:
                    screen.action_validate()
                    push.assert_not_called()

    async def test_validation_rejects_negative_missing_and_stale_rows(self):
        """Neither keyboard validation nor old Enter events choose a fallback."""
        inv = inventory(disabled=(("first", "sshd"), ("second", "sshd")))
        app = OffendersApp()
        async with app.run_test():
            await app.workers.wait_for_complete()
            await app.push_screen(ValidationScreen(inv, inv.findings[0]))
            screen = app.screen
            table = screen.query_one(DataTable)
            key = next(iter(table.rows))
            with patch.object(screen, "_validate") as run:
                with patch.object(DataTable, "cursor_coordinate", new_callable=PropertyMock,
                                  return_value=Coordinate(-1, 0)):
                    screen.action_validate()
                screen.on_data_table_row_selected(DataTable.RowSelected(table, -1, None))
                table.remove_row(key)
                screen.on_data_table_row_selected(DataTable.RowSelected(table, 0, key))
                run.assert_not_called()
                table.move_cursor(row=0)
                screen.action_validate()
                run.assert_called_once_with(screen.targets[1])
