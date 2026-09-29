"""Acquisition-free report export with a persistent, copyable result path."""
from textual import work
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Static
from textual.worker import get_current_worker

from offenders_activity import OffendersFooter
from offenders_export import SCHEMAS, default_root, export_report


class ExportScreen(Screen):
    """Retain the exact report selected on opening, independently of refreshes."""

    BINDINGS = [("e", "export", "Export"), ("c", "copy_path", "Copy path"),
                ("escape", "close", "Close"), ("q", "close", "Close")]
    DEFAULT_CSS = """
    ExportScreen { layout: vertical; }
    #export-scroll { height: 1fr; padding: 1; }
    #export-status { text-style: bold; margin-top: 1; }
    #export-path { color: $accent; margin-top: 1; }
    """

    def __init__(self, report, query=""):
        super().__init__()
        self.report = report
        self.dashboard_query = query
        self.root = default_root()
        self.path = None
        self._active = False
        self._delivery_closed = False

    def compose(self) -> ComposeResult:
        """Show committed metadata and scope before any filesystem write."""
        report = self.report
        scope = (f'Current dashboard filter "{self.dashboard_query}" is display-only and will not be applied'
                 if self.dashboard_query else "Dashboard filter is not applied")
        with VerticalScroll(id="export-scroll"):
            yield Static(
                f"Export report\nPeriod: {report.period}\nGenerated: {report.generated_at.isoformat()}\n"
                f"Historical ban events: {report.total_bans}\nDestination root: {self.root}\n"
                + "Files: " + ", ".join(SCHEMAS) + f"\n{scope}\n"
                "Summary mode does not affect contents. Jail status is current state, independent of period.",
                markup=False,
            )
            yield Static("Press e to export", id="export-status", markup=False)
            yield Static("", id="export-path", markup=False)
        yield OffendersFooter()

    def check_action(self, action, parameters):
        """Expose copy only while an exact successful path is retained."""
        if action == "copy_path":
            return self.path is not None and not self._active and not self._delivery_closed
        return True

    def action_export(self):
        """Start one worker without acquiring or changing report data."""
        if self._active:
            self.app.notify("Export already in progress", timeout=2.0)
            return
        if self._delivery_closed:
            return
        self._active = True
        self.path = None
        self.query_one("#export-path", Static).update("")
        self.query_one("#export-status", Static).update("Exporting…")
        self.refresh_bindings()
        self._export()

    @work(thread=True, name="activity:Exporting…")
    def _export(self):
        """Finish filesystem cleanup even if closing cancels UI delivery."""
        worker, app = get_current_worker(), self.app
        try:
            path, error = export_report(self.report, self.root), None
        except Exception as failure:
            path = None
            error = "Export failed: " + (" ".join(str(failure).split())[:240] or type(failure).__name__)
        if not worker.is_cancelled:
            app.call_from_thread(self._complete, path, error, worker)

    def _complete(self, path, error, worker=None):
        """Keep successful paths visible until close or another export."""
        if self._delivery_closed or not self.is_mounted or (worker is not None and worker.is_cancelled):
            return
        self._active = False
        self.path = path
        self.query_one("#export-status", Static).update(error or "Export complete")
        self.query_one("#export-path", Static).update(str(path) if path else "")
        self.query_one("#export-scroll", VerticalScroll).scroll_end(animate=False)
        self.refresh_bindings()

    def action_copy_path(self):
        """Use the established clipboard/stdout fallback for the retained path."""
        if self.path is None or self._active or self._delivery_closed:
            return
        text = str(self.path)
        try:
            self.app.copy_to_clipboard(text)
            self.app.notify("Copied path", timeout=1.0)
        except Exception:
            print(text)
            self.app.notify("Clipboard unavailable (printed to stdout)", timeout=2.0)

    def action_close(self):
        """Close presentation; an already running atomic write may finish."""
        self._delivery_closed = True
        self.workers.cancel_node(self)
        self.dismiss()

    def on_unmount(self):
        """Prevent delivery after external removal as well."""
        self._delivery_closed = True
