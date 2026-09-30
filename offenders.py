#!/usr/bin/env python3
"""Textual dashboard, keyboard actions, and source/installed entrypoints."""
from __future__ import annotations

import datetime as dt
import ipaddress
import sys
import threading
from typing import Optional, Tuple

from textual import events, on, work
from textual.app import App, ComposeResult
from textual.containers import Container
from textual.worker import Worker, get_current_worker
from rich.text import Text
from textual.widgets import DataTable, Header, Input, Static

from offenders_selection import current_row_key, event_row_key
from offenders_activity import ActivityWorkers, OffendersFooter
from offenders_help import HelpScreen, context_text, help_context
from offenders_help_content import HELP_BINDING, installed_version, project_information
from offenders_export_ui import ExportScreen
from offenders_enforcement_ui import EnforcementScreen
from offenders_filter import filter_rows
from offenders_summary_ui import DashboardSummary
from offenders_recommendations_ui import RecommendationsScreen
from offenders_jail_ui import JailDetailScreen
from offenders_ip_ui import CommandOutputModal, IPInspectorScreen
from offenders_geoip_ui import GeoIPScreen, GeoIPStatus
from offenders_fail2ban import Fail2BanCommandError, Fail2BanParseError
from offenders_report import DEFAULT_PERIOD, PERIODS, Report, build_report

# Do not set lower than 30 seconds as geoip/asn lookups may be slow
CHECK_INTERVAL_SECONDS = 30


class DashboardFilter(Input):
    """Escape clears this transient query and returns to the dashboard table."""

    def check_consume_key(self, key: str, character: str | None) -> bool:
        """Reserve ? for global Help even while editing the filter."""
        return False if character == "?" else super().check_consume_key(key, character)

    def on_key(self, event: events.Key) -> None:
        """Consume Escape locally so it cannot dismiss another screen."""
        if event.key == "escape":
            event.stop()
            event.prevent_default()
            self.value = ""
            self.screen.query_one("#offenders", DataTable).focus()


class SummaryBar(Static):
    def update_from_report(self, r: Report) -> None:
        now = r.generated_at
        self.update(
            f"🕒 {now:%Y-%m-%d %H:%M:%S} | 🔢 bans={r.total_bans} | period={r.period}"
            + f" | reports updating every {CHECK_INTERVAL_SECONDS} seconds"
        )


class OffendersApp(App):
    CSS = """
    Screen { layout: vertical; }

    #body { height: 1fr; padding: 1; }
    #summary { padding: 0 0 1 0; }

    .section-title { padding: 1 0 0 0; }

    /* Keep everything fitting so the bottom table isn't clipped */
    #offenders { height: 10; }
    #jails-line { height: auto; }
    #bans-per-jail { height: 7; }

    /* Bottom table uses the remaining space (and will scroll internally) */
    #last-bans { height: 1fr; min-height: 6; }
    """

    # Consolidated copy action: copies row in row-cursor mode, copies cell in cell-cursor mode
    BINDINGS = [
        HELP_BINDING,
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("p", "period", "Period"),
        ("f", "filter", "Filter"),
        ("v", "view", "View"),
        ("a", "coverage", "Coverage"),
        ("n", "enforcement", "Enforcement"),
        ("e", "export", "Export"),
        ("g", "geoip", "GeoIP"),
        ("c", "copy_selection", "Copy"),
        ("x", "copy_selection", "Copy"),
        ("t", "toggle_cursor", "Row/Cell"),
        ("w", "registration", "Registration"),
        ("d", "rdns", "RDNS"),
    ]

    def __init__(self) -> None:
        """Track scheduled work and actual thread lifetime separately on cancellation."""
        super().__init__()
        self._workers = ActivityWorkers(self)
        self._help_project_info = project_information()
        self._refresh_worker: Optional[Worker] = None
        self._build_lock = threading.Lock()
        self._active_period = DEFAULT_PERIOD
        self._last_success: Optional[dt.datetime] = None
        self._last_report: Optional[Report] = None
        self.summary_view = DashboardSummary()
        self.geoip_status = GeoIPStatus(self.refresh_report)

    def compose(self) -> ComposeResult:
        yield Header()

        with Container(id="body"):
            yield SummaryBar("Unavailable: awaiting first successful refresh", id="summary")
            yield self.geoip_status
            yield DashboardFilter(placeholder="Filter IP, jail, Country, ASN, organization", id="filter")

            yield self.summary_view
            yield DataTable(id="offenders")

            yield Static("🧱 Current active jails", classes="section-title")
            yield Static("", id="jails-line")

            yield Static("📊 Active bans per jail", classes="section-title")
            yield DataTable(id="bans-per-jail")

            yield Static("🕒 Last bans from selected logs", classes="section-title")
            yield DataTable(id="last-bans")

        yield OffendersFooter()

    def on_mount(self) -> None:
        self.title = "Fail2Ban Top Offenders"
        self.sub_title = "Updated at: —"

        offenders = self.query_one("#offenders", DataTable)
        offenders.add_columns("Bans", "IP", "Country", "ASN", "Org")
        offenders.cursor_type = "row"

        bans_per_jail = self.query_one("#bans-per-jail", DataTable)
        bans_per_jail.add_columns("Jail", "Currently banned")
        bans_per_jail.cursor_type = "row"

        last_bans = self.query_one("#last-bans", DataTable)
        last_bans.add_columns("Date", "Time", "Jail", "IP")
        last_bans.cursor_type = "row"

        # Ensure scrollbars are enabled for the widget
        last_bans.show_vertical_scrollbar = True
        last_bans.show_horizontal_scrollbar = True

        offenders.focus()
        self.refresh_report()
        self.set_interval(CHECK_INTERVAL_SECONDS, self.refresh_report)

    @on(DataTable.RowSelected, "#bans-per-jail")
    @on(DataTable.CellSelected, "#bans-per-jail")
    def open_jail(self, event: DataTable.RowSelected | DataTable.CellSelected) -> None:
        """Open only a real jail identity from the latest successful report."""
        key = event_row_key(event)
        if key is None:
            return
        jail = key.value
        if self._last_report is None or jail not in self._last_report.jail_list:
            return
        self.push_screen(
            JailDetailScreen(jail, self._last_report, self._push_ip),
            lambda result: self._restore_jail_focus(jail),
        )

    def _push_jail(self, jail: str) -> None:
        """Push nested jail detail without replacing the underlying inspector."""
        if self._last_report is not None:
            self.push_screen(JailDetailScreen(jail, self._last_report, self._push_ip))

    def _push_ip(self, ip: str) -> None:
        """Share report-only routing with jail history."""
        if self._last_report is not None:
            self.push_screen(IPInspectorScreen(ip, self._last_report, self._push_jail))

    @on(DataTable.RowSelected, "#offenders, #last-bans")
    @on(DataTable.CellSelected, "#offenders, #last-bans")
    def open_ip(self, event: DataTable.RowSelected | DataTable.CellSelected) -> None:
        """Capture IP identity for both opening and dashboard return selection."""
        if event_row_key(event) is None:
            return
        ip = self._selected_ip(event.data_table)
        if ip is None or self._last_report is None:
            return
        table = event.data_table
        self.push_screen(IPInspectorScreen(ip, self._last_report, self._push_jail),
                         lambda result: self._restore_ip_focus(table, ip))

    def _restore_ip_focus(self, table: DataTable, ip: str) -> None:
        """Restore a surviving IP identity; otherwise keep the new table selection."""
        column = 1 if table.id == "offenders" else 3
        row = next((i for i in range(table.row_count)
                    if str(table.get_row_at(i)[column]) == ip), None)
        if row is not None:
            table.move_cursor(row=row)
        table.focus()

    def _restore_jail_focus(self, jail: str) -> None:
        """Reselect the viewed jail if active, including after disappearance/reappearance."""
        table = self.query_one("#bans-per-jail", DataTable)
        if jail in table.rows:
            table.move_cursor(row=table.get_row_index(jail))
        table.focus()

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        """Share context availability across native bindings and action invocation."""
        if action == "help":
            return help_context(self) is not None
        if action in ("quit", "filter", "view", "coverage", "enforcement", "export", "geoip",
                      "registration", "rdns"):
            return self.screen is self.default_screen
        if action in ("refresh", "period"):
            return self.screen is self.default_screen or isinstance(self.screen, (JailDetailScreen, IPInspectorScreen))
        if action in ("copy_selection", "toggle_cursor"):
            table = self.focused
            if help_context(self) is None or not isinstance(table, DataTable):
                return False
            return action == "toggle_cursor" or self._copyable_selection(table)
        return super().check_action(action, parameters)

    @on(DataTable.RowHighlighted)
    @on(DataTable.CellHighlighted)
    def refresh_table_bindings(self, event: DataTable.RowHighlighted | DataTable.CellHighlighted) -> None:
        """Refresh copy availability when the focused table's selection changes."""
        if event.data_table is self.focused:
            self.screen.refresh_bindings()

    def action_help(self) -> None:
        """Push a local guide while preserving the exact underlying screen."""
        context = help_context(self)
        if context is not None:
            source = self if self.screen is self.default_screen else self.screen
            inherited = self.BINDINGS if source is not self else ()
            self.push_screen(HelpScreen(context_text(context, source.BINDINGS, inherited), self._help_project_info))

    def action_export(self) -> None:
        """Open the committed report only from the dashboard, without acquisition."""
        if self.screen is not self.default_screen:
            return
        if self._last_report is None:
            self.notify("No successful report to export", timeout=2.0)
            return
        self.push_screen(ExportScreen(self._last_report, self.query_one("#filter", Input).value))

    def action_coverage(self) -> None:
        """Open one manual analysis only from the active dashboard."""
        if self.screen is self.default_screen:
            self.push_screen(RecommendationsScreen())

    def action_enforcement(self) -> None:
        """Start manual verification only from the active dashboard."""
        if self.screen is self.default_screen:
            self.push_screen(EnforcementScreen())

    def action_view(self) -> None:
        """Keep summary cycling local to the dashboard screen."""
        if self.screen is self.default_screen:
            self.summary_view.cycle()

    def action_filter(self) -> None:
        """Focus the query only when the dashboard is the active screen."""
        if self.screen is self.default_screen:
            self.query_one("#filter", Input).focus()

    @on(Input.Changed, "#filter")
    def filter_changed(self) -> None:
        """Reproject the last successful snapshot without scheduling collection."""
        if self._last_report is not None:
            self._render_history(self._last_report)

    @on(Input.Submitted, "#filter")
    def filter_submitted(self) -> None:
        """Keep the visible query active when returning to table navigation."""
        self.query_one("#offenders", DataTable).focus()

    def action_geoip(self) -> None:
        """Open GeoIP health and lifecycle actions only from the dashboard."""
        if self.screen is self.default_screen:
            self.push_screen(GeoIPScreen(self.geoip_status))

    def action_refresh(self) -> None:
        """Manual refresh shares the timer gate but reports skipped requests."""
        if self.check_action("refresh", ()):
            self.refresh_report(manual=True)

    def action_period(self) -> None:
        """Request the next fixed period without changing committed report state."""
        if not self.check_action("period", ()):
            return
        keys = tuple(PERIODS)
        target = keys[(keys.index(self._active_period) + 1) % len(keys)]
        self.refresh_report(manual=True, period=target)

    def refresh_report(self, *, manual: bool = False, period: Optional[str] = None) -> None:
        """Schedule at most one build; all callers run on the UI thread."""
        # Cancellation before task startup may leave Textual's state PENDING.
        pending = (
            self._refresh_worker is not None
            and not self._refresh_worker.is_finished
            and not self._refresh_worker.is_cancelled
        )
        if pending or self._build_lock.locked():
            if manual:
                self.notify("Refresh already in progress", timeout=2.0)
            return
        target = period or self._active_period
        self._refresh_worker = self._collect_report(target)
        self.workers.label(self._refresh_worker,
                           f"Loading {target}…" if target != self._active_period else "Refreshing…")

    @work(thread=True)
    def _collect_report(self, period: str) -> None:
        """Keep cancellation from releasing the gate while a thread still builds."""
        worker = get_current_worker()
        with self._build_lock:
            if worker.is_cancelled:
                return
            try:
                report = build_report(period=period)
            except Exception as error:
                if not worker.is_cancelled:
                    self.call_from_thread(self._finish_refresh, worker, None, error)
            else:
                if not worker.is_cancelled:
                    self.call_from_thread(self._finish_refresh, worker, report, None)

    def _finish_refresh(
        self, worker: Worker, report: Optional[Report], error: Optional[Exception]
    ) -> None:
        """Discard cancelled completions on the UI thread before touching widgets."""
        if worker is not self._refresh_worker or worker.is_cancelled:
            return
        if error is not None:
            self._show_refresh_error(error)
        else:
            assert report is not None
            self._apply_report(report)

    def _show_refresh_error(self, error: Exception) -> None:
        """Render a bounded plain-text failure while retaining trustworthy tables."""
        category = "collection-failure"
        if isinstance(error, Fail2BanCommandError):
            category = error.result.failure.value
        elif isinstance(error, Fail2BanParseError):
            category = "parse-failure"
        detail = " ".join(str(error).split())
        detail = "".join(char for char in detail if char.isprintable())
        if len(detail) > 160:
            detail = detail[:159] + "…"
        if self._last_success is None:
            state = "Unavailable: no successful refresh"
        else:
            state = f"Showing last successful {self._active_period} refresh {self._last_success:%Y-%m-%d %H:%M:%S}"
        self.query_one("#summary", SummaryBar).update(Text(
            f"Degraded {dt.datetime.now():%Y-%m-%d %H:%M:%S} | {category}: {detail} | {state}"
        ))

    def _copy_text(self, text: str) -> None:
        # Clipboard support depends on terminal/OS; fallback prints.
        try:
            self.copy_to_clipboard(text)
            self.notify("Copied", timeout=1.0)
        except Exception:
            print(text)
            self.notify("Clipboard unavailable (printed to stdout)", timeout=2.0)

    def _selected_ip(self, table: DataTable | None = None) -> Optional[str]:
        """Resolve only a real current IP row backed by a committed report."""
        if self._last_report is None:
            return None
        table = self.focused if table is None else table
        if not isinstance(table, DataTable):
            return None

        idx = self._cursor_indexes(table)
        if idx is None:
            return None
        row_index, _ = idx

        ip_col = None
        if table.id == "offenders":
            if self.summary_view.mode != "IP":
                return None
            ip_col = 1  # Bans, IP, Country, ASN, Org
        elif table.id == "last-bans":
            ip_col = 3  # Date, Time, Jail, IP
        else:
            return None

        val = self._cell_value_at(table, row_index, ip_col)
        if val is None:
            return None

        ip = str(val).strip()
        try:
            return ipaddress.ip_address(ip).compressed
        except ValueError:
            return None

    def _open_ip_tool(self, tool: str) -> None:
        """Route dashboard tools to the shared bounded command view."""
        if self.screen is not self.default_screen:
            return
        ip = self._selected_ip()
        if ip:
            self.push_screen(CommandOutputModal(ip, tool))
        else:
            self.notify("Select an IP in the Top banned IPs or Last bans tables", timeout=2.0)

    def action_registration(self) -> None:
        """Preserve the dashboard registration binding."""
        self._open_ip_tool("registration")

    def action_rdns(self) -> None:
        """Preserve the dashboard reverse DNS binding."""
        self._open_ip_tool("rdns")

    # ---- Copy helpers (robust across Textual versions) ----

    def _cursor_indexes(self, table: DataTable) -> Optional[Tuple[int, int]]:
        """Return bounded display coordinates; focus alone is not selection."""
        if current_row_key(table) is None:
            return None
        column = table.cursor_column
        if table.cursor_type == "cell" and not 0 <= column < len(table.columns):
            return None
        return table.cursor_row, column

    def _row_values_at(self, table: DataTable, row_index: int) -> list[object]:
        """Read only rows that still exist in the displayed table."""
        return table.get_row_at(row_index) if 0 <= row_index < table.row_count else []

    def _cell_value_at(
        self, table: DataTable, row_index: int, col_index: int
    ) -> Optional[object]:
        """Keep missing cells distinct from valid empty strings and numeric zero."""
        row = self._row_values_at(table, row_index)
        return row[col_index] if 0 <= col_index < len(row) else None

    # ---- Consolidated copy action ----

    def _copyable_selection(self, table: DataTable) -> bool:
        """Reuse current selection and dashboard identity guards for copy availability."""
        if self._cursor_indexes(table) is None:
            return False
        if table.id == "bans-per-jail":
            key = current_row_key(table)
            if self._last_report is None or key is None or key.value not in self._last_report.jail_list:
                return False
        if table.id == "offenders" and self.summary_view.mode != "IP":
            return self.summary_view.copyable()
        elif table.id in ("offenders", "last-bans") and self._selected_ip() is None:
            return False
        return True

    def action_copy_selection(self) -> None:
        """Copy only a valid focused product table row or cell."""
        table = self.focused
        if not self.check_action("copy_selection", ()):
            return

        idx = self._cursor_indexes(table)
        if idx is None:
            return

        row_index, col_index = idx

        # In row mode, copy entire row (even if we also have a column)
        if table.cursor_type == "row":
            row = self._row_values_at(table, row_index)
            if not row:
                return
            self._copy_text("\t".join(str(v) for v in row))
            return

        # In cell mode, copy cell value
        val = self._cell_value_at(table, row_index, col_index)
        if val is None:
            return
        self._copy_text(str(val))

    # Backwards-compatible action names (in case you kept old keybindings elsewhere)
    def action_copy_row(self) -> None:
        table = self.focused
        if isinstance(table, DataTable):
            old = table.cursor_type
            table.cursor_type = "row"
            try:
                self.action_copy_selection()
            finally:
                table.cursor_type = old

    def action_copy_cell(self) -> None:
        table = self.focused
        if isinstance(table, DataTable):
            old = table.cursor_type
            table.cursor_type = "cell"
            try:
                self.action_copy_selection()
            finally:
                table.cursor_type = old

    def action_toggle_cursor(self) -> None:
        """Toggle cursor mode only for a focused product DataTable."""
        table = self.focused
        if not self.check_action("toggle_cursor", ()):
            return

        if table.cursor_type == "row":
            table.cursor_type = "cell"
        else:
            table.cursor_type = "row"

    def _apply_report(self, r: Report) -> None:
        """Replace all report widgets together in one UI callback after success."""
        summary = self.query_one("#summary", SummaryBar)
        jails_line = self.query_one("#jails-line", Static)
        bans_per_jail = self.query_one("#bans-per-jail", DataTable)

        selected_jail = current_row_key(bans_per_jail)
        bans_per_jail.clear()

        self._last_report = r
        self._active_period = r.period
        self._last_success = r.generated_at

        summary.update_from_report(r)
        self.geoip_status.set_health(r.geoip_health)
        self.sub_title = f"Updated at: {r.generated_at:%Y-%m-%d %H:%M:%S}"

        self._render_history(r)

        # Active jails line
        jails_line.update(", ".join(r.jail_list) if r.jail_list else "(no jails found)")

        # Bans per jail table
        if r.bans_per_jail:
            for jail, c in r.bans_per_jail:
                bans_per_jail.add_row(jail, str(c), key=jail)
        else:
            bans_per_jail.add_row("(none)", "0")

        if selected_jail in bans_per_jail.rows:
            bans_per_jail.move_cursor(row=bans_per_jail.get_row_index(selected_jail))
        for screen in self.screen_stack:
            if isinstance(screen, (JailDetailScreen, IPInspectorScreen)):
                screen.update_report(r)

    def _render_history(self, r: Report) -> None:
        """Render both historical tables through one in-memory visibility path."""
        rows = filter_rows(r, self.query_one("#filter", Input).value)
        self.summary_view.render_report(r)
        last_bans = self.query_one("#last-bans", DataTable)
        last_bans.clear()

        # Last bans table: render the normalized history without parsing raw text.
        if rows.last_bans:
            for event in rows.last_bans:
                last_bans.add_row(
                    event.timestamp.strftime("%Y-%m-%d"),
                    event.timestamp.strftime("%H:%M:%S"), event.jail, event.ip,
                )
        else:
            last_bans.add_row("", "", "", "(no filter matches)" if rows.query else "(no ban lines in selected period)")


# Static CLI discovery; each subcommand parser owns its detailed options.
CLI_HELP = """Usage:
  offenders                   Open the TUI
  offenders export [OPTIONS]
  offenders geoip COMMAND
  offenders --help | -h
  offenders --version | -V

Commands:
  export    Build one fresh report and export CSV
  geoip     Inspect/update local GeoIP data

Run 'offenders export --help' or 'offenders geoip --help' for command options."""


def main(argv=None):
    """Keep bare TUI launch, local singleton discovery, and explicit dispatch."""
    args = sys.argv[1:] if argv is None else argv
    if not args:
        OffendersApp().run()
        return 0
    if len(args) == 1 and args[0] in ("--help", "-h"):
        print(CLI_HELP)
        return 0
    if len(args) == 1 and args[0] in ("--version", "-V"):
        print(f"offenders {installed_version() or '(source development)'}")
        return 0
    if args[0] == "export":
        from offenders_export_cli import main as export_main
        return export_main(args[1:])
    if args[0] == "geoip":
        from offenders_geoip_cli import main as geoip_main
        return geoip_main(args[1:])
    print("Usage: offenders [export ... | geoip ... | --help | -h | --version | -V]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
