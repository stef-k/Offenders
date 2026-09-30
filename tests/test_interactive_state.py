"""Invalid selections must never become a different row's action."""
from dataclasses import replace
import unittest
from unittest.mock import patch, PropertyMock

from textual.coordinate import Coordinate
from textual.widgets.data_table import CellKey, RowKey, ColumnKey
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
                screen._complete(inv, None, '7d')
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
                run.reset_mock()
                screen._active = False
                table.clear()
                screen.action_validate()
                run.assert_not_called()

    async def test_dashboard_invalid_copy_navigation_and_refresh(self):
        """Invalid cursors and removed identities neither copy nor navigate."""
        app = OffendersApp()
        async with app.run_test() as pilot:
            await app.workers.wait_for_complete()
            source = app._last_report
            with patch.object(app, "_copy_text") as copy, patch.object(app, "push_screen") as push:
                for selector, handler in (("#bans-per-jail", app.open_jail),
                                          ("#offenders", app.open_ip), ("#last-bans", app.open_ip)):
                    table = app.query_one(selector, DataTable)
                    table.focus()
                    await pilot.pause()
                    key = next(iter(table.rows))
                    for row in (-1, table.row_count):
                        with patch.object(DataTable, "cursor_coordinate", new_callable=PropertyMock,
                                          return_value=Coordinate(row, 0)):
                            app.action_copy_selection()
                            app.action_registration()
                            app.action_rdns()
                            handler(DataTable.RowSelected(table, row, key))
                            self.assertFalse(app.summary_view.copyable())
                    handler(DataTable.RowSelected(table, -1, None))
                    handler(DataTable.CellSelected(table, "", Coordinate(-1, -1),
                                                   CellKey(RowKey("missing"), ColumnKey("missing"))))
                    table.clear()
                    handler(DataTable.RowSelected(table, 0, key))
                    app.action_copy_selection()
                copy.assert_not_called()
                push.assert_not_called()
                # A bad cursor cannot prevent a successful report commit.
                with patch.object(DataTable, "cursor_coordinate", new_callable=PropertyMock,
                                  return_value=Coordinate(99, 0)):
                    app._apply_report(source)
                table = app.query_one("#offenders", DataTable)
                table.focus()
                await pilot.pause()
                app._last_report = None
                app.open_ip(DataTable.RowSelected(table, 0, next(iter(table.rows))))
                app.action_registration()
                app.action_rdns()
                push.assert_not_called()
                empty = replace(source, events=[], top_offenders=[], jail_statuses=[])
                app._apply_report(empty)
                for table in app.query(DataTable):
                    table.focus()
                    await pilot.pause()
                    app.action_copy_selection()
                copy.assert_not_called()
                self.assertIn("bans=0", str(app.query_one("#summary", Static).content))

    async def test_dashboard_event_uses_its_identity_not_focused_table(self):
        """Queued events cannot silently route the IP from another focused table."""
        app = OffendersApp()
        async with app.run_test():
            await app.workers.wait_for_complete()
            table = app.query_one("#offenders", DataTable)
            key = next(iter(table.rows))
            app.query_one("#bans-per-jail", DataTable).focus()
            with patch.object(app, "push_screen") as push:
                app.open_ip(DataTable.RowSelected(table, 0, key))
                self.assertEqual(push.call_args.args[0].ip, "8.8.8.8")
                push.reset_mock()
                table.clear()
                table.add_row("1", "1.1.1.1", "", "", "", key="1.1.1.1")
                app.open_ip(DataTable.RowSelected(table, 0, key))
                push.assert_not_called()

    async def test_jail_history_and_ip_jails_reject_removed_events(self):
        """Empty detail tables ignore old row and cell selections after refresh."""
        from offenders_ip_ui import IPInspectorScreen
        from offenders_jail_ui import JailDetailScreen
        app = OffendersApp()
        async with app.run_test():
            await app.workers.wait_for_complete()
            source = app._last_report
            for screen, selector, handler_name in (
                (JailDetailScreen("sshd", source, lambda value: None), "#jail-history", "select_ip"),
                (IPInspectorScreen("8.8.8.8", source, lambda value: None), "#ip-jails", "select_jail"),
            ):
                await app.push_screen(screen)
                await app.workers.wait_for_complete()
                table = screen.query_one(selector, DataTable)
                handler = getattr(screen, handler_name)
                callback = "open_ip" if handler_name == "select_ip" else "open_jail"
                key = next(iter(table.rows))
                cell = table.coordinate_to_cell_key((0, 0))
                with patch.object(screen, callback) as navigate:
                    handler(DataTable.RowSelected(table, -1, None))
                    handler(DataTable.CellSelected(table, "", Coordinate(-1, -1),
                                                   CellKey(RowKey("missing"), ColumnKey("missing"))))
                    with patch.object(DataTable, "cursor_coordinate", new_callable=PropertyMock,
                                      return_value=Coordinate(-1, 0)):
                        handler(DataTable.RowSelected(table, -1, key))
                    navigate.assert_not_called()
                    handler(DataTable.RowSelected(table, 0, key))
                    navigate.assert_called_once()
                    navigate.reset_mock()
                    empty = replace(source, events=[], top_offenders=[], jail_statuses=[])
                    if isinstance(screen, IPInspectorScreen):
                        with patch.object(screen, "_project"):
                            screen.update_report(empty)
                            handler(DataTable.RowSelected(table, 0, key))
                            navigate.assert_not_called()
                    screen.update_report(empty)
                    await app.workers.wait_for_complete()
                    self.assertEqual(table.row_count, 0)
                    handler(DataTable.RowSelected(table, 0, key))
                    handler(DataTable.CellSelected(table, "old", Coordinate(0, 0), cell))
                    navigate.assert_not_called()
                await app.pop_screen()
