"""Report-only IP inspection and explicit bounded network-tool presentation."""
from __future__ import annotations

import ipaddress
from collections.abc import Callable

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import DataTable, RichLog, Static
from textual.worker import get_current_worker

from offenders_selection import current_row_key, event_row_key
from offenders_activity import OffendersFooter
from offenders_help_content import HELP_BINDING
from offenders_lookup import lookup_output
from offenders_ip import IPProjection, project_ip
from offenders_report import Report

class CommandOutputModal(ModalScreen[None]):
    """Run an explicit lookup off-loop and retain literal, copyable output."""

    BINDINGS = [HELP_BINDING, ("escape", "dismiss", "Close"), ("q", "dismiss", "Close"),
                ("c", "copy_output", "Copy output")]

    def __init__(self, ip: str, tool: str) -> None:
        super().__init__()
        self.ip = ipaddress.ip_address(ip).compressed
        self.tool = tool
        self._output_text = ""
        self.working_text = "Querying RDAP…" if tool == "registration" else "Resolving PTR…"

    def compose(self) -> ComposeResult:
        """Show the chosen IP while its lookup is running."""
        yield Static(f"{self.tool.upper()} {self.ip}", markup=False)
        yield RichLog(id="cmd-out", wrap=True)
        yield OffendersFooter()

    def on_mount(self) -> None:
        """Start only after the output widget is mounted."""
        self.query_one("#cmd-out", RichLog).write(Text(self.working_text))
        worker = self._run()
        self.app.workers.label(worker, self.working_text)

    @work(thread=True)
    def _run(self) -> None:
        """Late completion must not mutate a dismissed command view."""
        worker = get_current_worker()
        output = lookup_output(self.ip, self.tool)
        if not worker.is_cancelled:
            self.app.call_from_thread(self._render_output, output, worker)

    def _render_output(self, output: str, worker=None) -> None:
        """Store precisely the bounded text shown and copied."""
        if (not self.is_mounted or self not in self.app.screen_stack
                or (worker is not None and worker.is_cancelled)):
            return
        self._output_text = output
        self.query_one("#cmd-out", RichLog).clear().write(Text(output))
        self.refresh_bindings()

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        """Offer output copy only after a nonempty result has been displayed."""
        if action == "copy_output":
            return bool(self._output_text and self.is_mounted and self in self.app.screen_stack)
        return True

    def action_copy_output(self) -> None:
        """Preserve terminal clipboard support and the stdout fallback."""
        if not self._output_text or not self.is_mounted or self not in self.app.screen_stack:
            return
        try:
            self.app.copy_to_clipboard(self._output_text)
            self.app.notify("Copied output", timeout=1.0)
        except Exception:
            print(self._output_text)
            self.app.notify("Clipboard unavailable (printed to stdout)", timeout=2.0)


def ip_details(projection: IPProjection) -> Text:
    """Present all snapshot fields, distinguishing healthy absence from failure."""
    p = projection
    lines = [f"IP: {p.ip}", f"Historical period: {p.period}",
             f"Latest successful report: {p.generated_at:%Y-%m-%d %H:%M:%S}",
             f"Historical bans: {p.total_bans}",
             f"First seen: {p.first_seen or 'Unavailable'}",
             f"Last seen: {p.last_seen or 'Unavailable'}",
             f"Distinct historical jails: {p.distinct_jail_count}",
             f"Currently banned: {'Yes' if p.currently_banned else 'No'}",
             f"Current jails: {', '.join(p.current_jails) or '(none)'}"]
    for label, result in (("Country", p.enrichment.country), ("ASN", p.enrichment.asn)):
        lines.append(f"{label}: {result.state}" + (f" — {result.value}" if result.value else ""))
        if result.organization:
            lines.append(f"Organization: {result.organization}")
        if result.detail:
            lines.append(f"{label} detail: {result.detail}")
    return Text("\n".join(lines))


class IPInspectorScreen(Screen[None]):
    """Keep one normalized IP and navigation context across successful reports."""

    BINDINGS = [("escape", "dismiss", "Back"), ("q", "dismiss", "Back"),
                ("w", "registration", "Registration"), ("d", "rdns", "RDNS")]
    DEFAULT_CSS = """
    IPInspectorScreen #ip-jails { height: 8; }
    IPInspectorScreen #ip-events { height: 12; }
    """

    def __init__(self, ip: str, report: Report, open_jail: Callable[[str], None]) -> None:
        super().__init__()
        self.ip = ipaddress.ip_address(ip).compressed
        self.report = report
        self.open_jail = open_jail
        self.projection: IPProjection | None = None
        self._request = 0

    def compose(self) -> ComposeResult:
        """Mount stable tables once, with a visible initial loading state."""
        with VerticalScroll():
            yield Static(f"IP: {self.ip}\nLoading…", id="ip-details", markup=False)
            yield DataTable(id="ip-jails", cursor_type="row")
            yield Static("Recent historical events (newest ten)")
            yield DataTable(id="ip-events", cursor_type="row")
        yield OffendersFooter()

    def on_mount(self) -> None:
        """Initialize table schemas before scheduling the local projection."""
        self.query_one("#ip-jails", DataTable).add_columns("Jail", "Period bans", "Current")
        self.query_one("#ip-events", DataTable).add_columns("Date", "Time", "Jail", "IP")
        self.update_report(self.report)

    def update_report(self, report: Report) -> None:
        """Invalidate older completions immediately on each successful report."""
        self.report = report
        self._request += 1
        self._project(report, self._request)

    @work(thread=True, name="activity:Loading IP details…")
    def _project(self, report: Report, request: int) -> None:
        """MMDB lookup is local but must never block the Textual event loop."""
        worker = get_current_worker()
        projection = project_ip(report, self.ip)
        if not worker.is_cancelled:
            self.app.call_from_thread(self._accept_projection, request, projection)

    def _accept_projection(self, request: int, projection: IPProjection) -> None:
        """Reject stale or closed-screen results before touching any widgets."""
        if request != self._request or not self.is_mounted or self not in self.app.screen_stack:
            return
        self.projection = projection
        self.query_one("#ip-details", Static).update(ip_details(projection))
        table = self.query_one("#ip-jails", DataTable)
        selected = current_row_key(table)
        cursor, x, y = table.cursor_coordinate, table.scroll_x, table.scroll_y
        table.clear()
        counts = dict(projection.jail_counts)
        for jail in (*counts, *(j for j in projection.current_jails if j not in counts)):
            table.add_row(jail, str(counts.get(jail, 0)),
                          "Yes" if jail in projection.current_jails else "No", key=jail)
        row = table.get_row_index(selected) if selected in table.rows else min(cursor.row, max(0, table.row_count - 1))
        table.move_cursor(row=row, column=cursor.column, scroll=False)
        table.scroll_to(x=x, y=y, animate=False, force=True)
        events = self.query_one("#ip-events", DataTable)
        cursor, x, y = events.cursor_coordinate, events.scroll_x, events.scroll_y
        events.clear()
        for event in projection.recent_events:
            events.add_row(event.timestamp.strftime("%Y-%m-%d"),
                           event.timestamp.strftime("%H:%M:%S"), event.jail, event.ip)
        events.move_cursor(row=min(cursor.row, max(0, events.row_count - 1)),
                           column=cursor.column, scroll=False)
        events.scroll_to(x=x, y=y, animate=False, force=True)

    @on(DataTable.RowSelected, "#ip-jails")
    @on(DataTable.CellSelected, "#ip-jails")
    def select_jail(self, event: DataTable.RowSelected | DataTable.CellSelected) -> None:
        """Push a historical or live jail without acquiring any new facts."""
        event.stop()
        key = event_row_key(event)
        if key is not None and key.value is not None:
            self.open_jail(key.value)

    def action_registration(self) -> None:
        """Always inspect this screen's fixed IP, independent of table focus."""
        self.app.push_screen(CommandOutputModal(self.ip, "registration"))

    def action_rdns(self) -> None:
        """Run reverse DNS only after the explicit keyboard action."""
        self.app.push_screen(CommandOutputModal(self.ip, "rdns"))
