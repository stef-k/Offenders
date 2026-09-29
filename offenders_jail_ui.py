"""Current jail detail rendered exclusively from successful dashboard reports."""

from collections.abc import Callable

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import DataTable, Static

from offenders_selection import event_row_key
from offenders_activity import OffendersFooter
from offenders_report import Report


def jail_details(jail: str, report: Report) -> Text:
    """Keep live counters distinct from history and preserve unavailable values."""
    lines = [
        f"Jail: {jail}",
        f"Historical period: {report.period}",
        f"Latest successful report: {report.generated_at:%Y-%m-%d %H:%M:%S}",
        "",
        "Current live jail status (not filtered by historical period)",
    ]
    status = next((status for status in report.jail_statuses if status.name == jail), None)
    if status is None:
        lines.append("Jail not active in latest successful refresh")
    else:
        for label, value in (
            ("Currently failed", status.currently_failed),
            ("Total failed", status.total_failed),
            ("Currently banned", status.currently_banned),
            ("Total banned", status.total_banned),
            ("Bantime (seconds)", status.bantime),
            ("Findtime (seconds)", status.findtime),
            ("Maxretry", status.maxretry),
            ("Backend", status.backend),
            ("Filter", status.filter_name),
        ):
            lines.append(f"{label}: {'Unavailable' if value is None else value}")
    lines.extend(["", "Current banned IPs (live Fail2Ban snapshot)"])
    if status is None:
        lines.append("Unavailable — jail not active in latest successful refresh")
    else:
        lines.extend(status.banned_ips or ("(none)",))
    return Text("\n".join(lines))


class JailDetailScreen(Screen[None]):
    """Retain jail identity and navigation while accepting successful snapshots."""

    BINDINGS = [
        ("escape", "dismiss", "Back"), ("q", "dismiss", "Back"),
        ("e", "expand_history", "Expand history"),
    ]
    DEFAULT_CSS = """
    JailDetailScreen #jail-history { height: 12; }
    """

    # None means all events in the committed report period.
    HISTORY_LIMITS = (10, 50, 100, None)

    def __init__(self, jail: str, report: Report, open_ip: Callable[[str], None]) -> None:
        super().__init__()
        self.open_ip = open_ip
        self.jail = jail
        self.report = report
        self.history_level = 0

    def compose(self) -> ComposeResult:
        """Mount the scroll surface once so refresh does not replace navigation."""
        with VerticalScroll():
            yield Static(jail_details(self.jail, self.report), id="jail-details")
            yield Static("", id="jail-history-summary")
            yield DataTable(id="jail-history", cursor_type="row")
        yield OffendersFooter()

    def on_mount(self) -> None:
        """Create the history columns once and project the initial snapshot."""
        self.query_one("#jail-history", DataTable).add_columns("Date", "Time", "IP")
        self._render_history()

    def action_expand_history(self) -> None:
        """Expand only this screen's presentation without collecting any data."""
        self.history_level = min(self.history_level + 1, len(self.HISTORY_LIMITS) - 1)
        self._render_history()

    def _render_history(self) -> None:
        """Project normalized events, retaining duplicates and stable timestamp ties."""
        events = sorted(
            (event for event in self.report.events if event.jail == self.jail),
            key=lambda event: event.timestamp, reverse=True,
        )
        visible = events[:self.HISTORY_LIMITS[self.history_level]]
        summary = (
            f"Historical bans in {self.report.period}: showing {len(visible)} "
            f"of {len(events)} (newest first)"
        )
        if not events:
            summary += "\nNo historical bans for this jail in the selected period."
        self.query_one("#jail-history-summary", Static).update(Text(summary))
        table = self.query_one("#jail-history", DataTable)
        cursor, scroll_x, scroll_y = table.cursor_coordinate, table.scroll_x, table.scroll_y
        table.clear()
        for event in visible:
            table.add_row(
                event.timestamp.strftime("%Y-%m-%d"),
                event.timestamp.strftime("%H:%M:%S"), event.ip,
            )
        if table.row_count:
            table.move_cursor(row=max(0, min(cursor.row, table.row_count - 1)), scroll=False)
        table.scroll_to(x=scroll_x, y=scroll_y, animate=False, force=True)

    @on(DataTable.RowSelected, "#jail-history")
    @on(DataTable.CellSelected, "#jail-history")
    def select_ip(self, event: DataTable.RowSelected | DataTable.CellSelected) -> None:
        """Open the report's normalized address without changing history context."""
        event.stop()
        key = event_row_key(event)
        if key is not None:
            self.open_ip(str(event.data_table.get_row(key)[2]))

    def update_report(self, report: Report) -> None:
        """Refresh literal status in place without changing focus or scroll."""
        self.report = report
        self.query_one("#jail-details", Static).update(jail_details(self.jail, report))
        self._render_history()
