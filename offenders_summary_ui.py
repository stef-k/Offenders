"""Dashboard summary modes, lazy worker ownership, and identity-guarded rendering."""
from textual import work
from textual.worker import get_current_worker
from textual.widgets import DataTable, Input, Static

from offenders_aggregate import AggregateSnapshot, aggregate_report, filter_aggregates
from offenders_filter import filter_rows
from offenders_geoip import geoip
from offenders_selection import current_row_key
from offenders_report import Report


class DashboardSummary(Static):
    """Own one current report projection, shared by ASN and Country views."""

    def __init__(self):
        super().__init__("🔥 Top banned IPs · IP", classes="section-title")
        self.mode = "IP"
        self.report: Report | None = None
        self.snapshot: AggregateSnapshot | None = None
        self.requested = False
        self.error = False

    def cycle(self) -> None:
        """Cycle only when routed by the active dashboard."""
        modes = ("IP", "ASN", "Country")
        self.mode = modes[(modes.index(self.mode) + 1) % len(modes)]
        self.render_report(self.report)

    def render_report(self, report: Report | None) -> None:
        """Invalidate only on a new successful report, never on filter edits."""
        if report is not self.report:
            self.report = report
            self.snapshot = None
            self.requested = False
            self.error = False
        self.update("🔥 Top banned IPs · IP" if self.mode == "IP" else f"🔥 {self.mode} · full-period bans")
        if report is None:
            return
        if self.mode != "IP" and not self.requested:
            self.requested = True
            self._project(report)
        self._render_table()

    @work(thread=True, name="activity:Loading summary…")
    def _project(self, report: Report) -> None:
        """Acquire local enrichment away from the UI loop; report failures safely."""
        worker = get_current_worker()
        try:
            snapshot = aggregate_report(report, geoip.lookup)
        except Exception:
            snapshot = None
        if not worker.is_cancelled:
            self.app.call_from_thread(self._complete, report, snapshot, worker)

    def _complete(self, report: Report, snapshot: AggregateSnapshot | None, worker=None) -> None:
        """An old completion cannot overwrite the current report or its IP view."""
        if (report is not self.report or not self.is_mounted
                or (worker is not None and worker.is_cancelled)):
            return
        self.snapshot = snapshot
        self.error = snapshot is None
        if self.mode != "IP":
            self._render_table()

    def copyable(self) -> bool:
        """Only real aggregate rows support normal row/cell copy."""
        table = self.screen.query_one("#offenders", DataTable)
        key = current_row_key(table)
        return key is not None and key.value is not None

    def _render_table(self) -> None:
        """Replace summary columns/rows while preserving a visible bucket identity."""
        table = self.screen.query_one("#offenders", DataTable)
        selected = current_row_key(table)
        query = self.screen.query_one("#filter", Input).value
        table.clear(columns=True)
        if self.mode == "IP":
            table.add_columns("Bans", "IP", "Country", "ASN", "Org")
            rows = filter_rows(self.report, query)
            for row in rows.top_offenders:
                asn = f"AS{row.asn}" if row.asn.isdigit() else row.asn
                table.add_row(str(row.count), row.ip, row.country, asn, row.asn_org, key=row.ip)
            if not rows.top_offenders:
                table.add_row("0", "(no filter matches)" if rows.query else "(none)", "", "", "")
        else:
            self._render_aggregates(table, query)
        if selected in table.rows:
            table.move_cursor(row=table.get_row_index(selected))

    def _render_aggregates(self, table: DataTable, query: str) -> None:
        """Render full counts after visibility filtering, including safe status rows."""
        columns = ("Bans", "IPs", self.mode, "Organization") if self.mode == "ASN" else ("Bans", "IPs", "Country")
        table.add_columns(*columns)
        if self.snapshot is None:
            message = "(aggregation unavailable)" if self.error else "(loading)"
            table.add_row(message, *([""] * (len(columns) - 1)))
            return
        rows = filter_aggregates(getattr(self.snapshot, self.mode.lower()), query)
        for row in rows:
            cells = [str(row.bans), str(row.distinct_ips), row.value]
            if self.mode == "ASN":
                cells.append(row.organization)
            table.add_row(*cells, key=f"{self.mode}:{row.identity!r}")
        if not rows:
            table.add_row("(no filter matches)" if query.strip() else "(none)",
                          *([""] * (len(columns) - 1)))
