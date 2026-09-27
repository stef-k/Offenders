#!/usr/bin/env python3
"""Textual dashboard, keyboard actions, and source/installed entrypoints."""
from __future__ import annotations

import datetime as dt
import ipaddress
import shutil
import subprocess
import sys
import threading
from typing import List, Optional, Tuple

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Container
from textual.screen import ModalScreen
from textual.worker import Worker, get_current_worker
from rich.text import Text
from textual.widgets import DataTable, Footer, Header, RichLog, Static

from offenders_geoip_ui import GeoIPScreen, GeoIPStatus
from offenders_fail2ban import Fail2BanCommandError, Fail2BanParseError
from offenders_report import LOOKBACK_DAYS, Report, build_report

# Do not set lower than 30 seconds as geoip/asn lookups may be slow
CHECK_INTERVAL_SECONDS = 30

def _format_period(cutoff: Optional[dt.date]) -> str:
    today = dt.date.today()
    if cutoff:
        return f"{cutoff.isoformat()} → {today.isoformat()} (last {LOOKBACK_DAYS} days)"
    return "all available logs"


class SummaryBar(Static):
    def update_from_report(self, r: Report) -> None:
        now = r.generated_at
        period = _format_period(r.cutoff_date)
        self.update(
            f"🕒 {now:%Y-%m-%d %H:%M:%S} | 🔢 bans={r.total_bans} | period={period}"
            + f" | reports updating every {CHECK_INTERVAL_SECONDS} seconds"
        )


class CommandOutputModal(ModalScreen[None]):
    BINDINGS = [
        ("escape", "dismiss", "Close"),
        ("q", "dismiss", "Close"),
        ("c", "copy_output", "Copy output"),
    ]

    def __init__(self, title: str, cmd: List[str]) -> None:
        super().__init__()
        self._title = title
        self._cmd = cmd
        self._output_text = ""

    def compose(self) -> ComposeResult:
        yield Static(self._title, id="cmd-title")
        yield RichLog(id="cmd-out", wrap=True, highlight=True)

    def on_mount(self) -> None:
        out = self.query_one("#cmd-out", RichLog)
        out.write(f"$ {' '.join(self._cmd)}")
        out.write("")
        self._run()

    @work(thread=True)
    def _run(self) -> None:
        out_text = ""
        try:
            p = subprocess.run(
                self._cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=8,
            )
            out_text = (p.stdout or "") + (p.stderr or "")
            if not out_text.strip():
                out_text = "(no output)"
        except FileNotFoundError:
            out_text = (
                "Command not found. Install the required package (whois / dnsutils)."
            )
        except subprocess.TimeoutExpired:
            out_text = "Command timed out."
        except Exception as ex:
            out_text = f"Command failed: {ex}"

        # Cap output so the UI stays responsive
        if len(out_text) > 200_000:
            out_text = out_text[:200_000] + "\n\n(output truncated)\n"

        self._output_text = out_text
        self.app.call_from_thread(self._render_output, out_text)

    def _render_output(self, text: str) -> None:
        out = self.query_one("#cmd-out", RichLog)
        for line in text.splitlines():
            out.write(line)

    def action_copy_output(self) -> None:
        if not self._output_text:
            return
        try:
            self.app.copy_to_clipboard(self._output_text)  # type: ignore[attr-defined]
            self.app.notify("Copied output", timeout=1.0)  # type: ignore[attr-defined]
        except Exception:
            print(self._output_text)
            self.app.notify("Clipboard unavailable (printed to stdout)", timeout=2.0)  # type: ignore[attr-defined]


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
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("g", "geoip", "GeoIP"),
        ("c", "copy_selection", "Copy"),
        ("x", "copy_selection", "Copy"),
        ("t", "toggle_cursor", "Row/Cell"),
        ("w", "whois", "Whois"),
        ("d", "rdns", "RDNS"),
    ]

    def __init__(self) -> None:
        """Track scheduled work and actual thread lifetime separately on cancellation."""
        super().__init__()
        self._refresh_worker: Optional[Worker] = None
        self._build_lock = threading.Lock()
        self._last_success: Optional[dt.datetime] = None
        self.geoip_status = GeoIPStatus(self.refresh_report)

    def compose(self) -> ComposeResult:
        yield Header()

        with Container(id="body"):
            yield SummaryBar("Unavailable: awaiting first successful refresh", id="summary")
            yield self.geoip_status

            yield Static("🔥 Top banned IPs", classes="section-title")
            yield DataTable(id="offenders")

            yield Static("🧱 Current active jails", classes="section-title")
            yield Static("", id="jails-line")

            yield Static("📊 Active bans per jail", classes="section-title")
            yield DataTable(id="bans-per-jail")

            yield Static("🕒 Last bans from selected logs", classes="section-title")
            yield DataTable(id="last-bans")

        yield Footer()

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
        # Removed raw line column; keep it clean
        last_bans.add_columns("Date", "Time", "Jail", "IP")
        last_bans.cursor_type = "row"

        # Ensure scrollbars are enabled for the widget
        last_bans.show_vertical_scrollbar = True
        last_bans.show_horizontal_scrollbar = True

        self.refresh_report()
        self.set_interval(CHECK_INTERVAL_SECONDS, self.refresh_report)

    def action_geoip(self) -> None:
        """Open focused GeoIP health and lifecycle actions."""
        self.push_screen(GeoIPScreen(self.geoip_status))

    def action_refresh(self) -> None:
        """Manual refresh shares the timer gate but reports skipped requests."""
        self.refresh_report(manual=True)

    def refresh_report(self, *, manual: bool = False) -> None:
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
        self._refresh_worker = self._collect_report()

    @work(thread=True)
    def _collect_report(self) -> None:
        """Keep cancellation from releasing the gate while a thread still builds."""
        worker = get_current_worker()
        with self._build_lock:
            if worker.is_cancelled:
                return
            try:
                report = build_report()
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
            state = f"Showing last successful refresh {self._last_success:%Y-%m-%d %H:%M:%S}"
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

    def _selected_ip(self) -> Optional[str]:
        table = self.focused
        if not isinstance(table, DataTable):
            return None

        idx = self._cursor_indexes(table)
        if idx is None:
            return None
        row_index, _ = idx

        ip_col = None
        if table.id == "offenders":
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
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            return None

    def action_whois(self) -> None:
        ip = self._selected_ip()
        if not ip:
            self.notify(
                "Select an IP in the Top banned IPs or Last bans tables", timeout=2.0
            )
            return

        if shutil.which("whois") is None:
            self.notify("Missing 'whois' command (install package: whois)", timeout=3.0)
            return

        self.push_screen(CommandOutputModal(f"WHOIS {ip}", ["whois", ip]))

    def action_rdns(self) -> None:
        ip = self._selected_ip()
        if not ip:
            self.notify(
                "Select an IP in the Top banned IPs or Last bans tables", timeout=2.0
            )
            return

        if shutil.which("dig") is not None:
            cmd = ["dig", "+short", "-x", ip]
            title = f"RDNS (dig -x) {ip}"
        else:
            # Fallback that works on most Linux systems without dnsutils
            cmd = ["getent", "hosts", ip]
            title = f"RDNS (getent hosts) {ip}"

        self.push_screen(CommandOutputModal(title, cmd))

    # ---- Copy helpers (robust across Textual versions) ----

    def _cursor_indexes(self, table: DataTable) -> Optional[Tuple[int, int]]:
        """
        Returns (row_index, col_index) in display order, if possible.
        Falls back to mapping row/col keys to indices.
        """
        coord = getattr(table, "cursor_coordinate", None)
        if coord is not None:
            try:
                return (coord.row, coord.column)
            except Exception:
                pass

        row_key = getattr(table, "cursor_row", None)
        col_key = getattr(table, "cursor_column", None)
        if row_key is None:
            return None

        try:
            row_keys = getattr(table, "row_keys", None)
            if row_keys is not None:
                row_index = list(row_keys).index(row_key)
            else:
                return None
        except Exception:
            return None

        if col_key is None:
            return (row_index, -1)

        try:
            # table.columns contains Column objects; compare by .key
            col_index = -1
            for i, col in enumerate(table.columns):
                if getattr(col, "key", None) == col_key:
                    col_index = i
                    break
            return (row_index, col_index)
        except Exception:
            return (row_index, -1)

    def _row_values_at(self, table: DataTable, row_index: int) -> Tuple[object, ...]:
        # Prefer direct index API if available
        if hasattr(table, "get_row_at"):
            return table.get_row_at(row_index)  # type: ignore[attr-defined]

        row_keys = getattr(table, "row_keys", None)
        if row_keys is None:
            return tuple()

        row_key = list(row_keys)[row_index]
        return table.get_row(row_key)

    def _cell_value_at(
        self, table: DataTable, row_index: int, col_index: int
    ) -> Optional[object]:
        if row_index < 0 or col_index < 0:
            return None

        # Prefer direct index API if available
        if hasattr(table, "get_cell_at"):
            try:
                return table.get_cell_at(row_index, col_index)  # type: ignore[attr-defined]
            except Exception:
                pass

        # Fall back to key-based cell access if possible
        try:
            row_keys = getattr(table, "row_keys", None)
            if row_keys is not None and col_index < len(table.columns):
                row_key = list(row_keys)[row_index]
                col_key = getattr(table.columns[col_index], "key", None)
                if col_key is not None:
                    return table.get_cell(row_key, col_key)
        except Exception:
            pass

        # Last resort: row tuple + column index
        try:
            row = self._row_values_at(table, row_index)
            if 0 <= col_index < len(row):
                return row[col_index]
        except Exception:
            pass

        return None

    # ---- Consolidated copy action ----

    def action_copy_selection(self) -> None:
        table = self.focused
        if not isinstance(table, DataTable):
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
        table = self.focused
        if not isinstance(table, DataTable):
            return

        if table.cursor_type == "row":
            table.cursor_type = "cell"
        else:
            table.cursor_type = "row"

    def _apply_report(self, r: Report) -> None:
        """Replace all report widgets together in one UI callback after success."""
        summary = self.query_one("#summary", SummaryBar)
        offenders = self.query_one("#offenders", DataTable)
        jails_line = self.query_one("#jails-line", Static)
        bans_per_jail = self.query_one("#bans-per-jail", DataTable)
        last_bans = self.query_one("#last-bans", DataTable)

        offenders.clear()
        bans_per_jail.clear()
        last_bans.clear()

        self._last_success = r.generated_at

        summary.update_from_report(r)
        self.geoip_status.set_health(r.geoip_health)
        self.sub_title = f"Updated at: {r.generated_at:%Y-%m-%d %H:%M:%S}"

        # Top offenders table
        if r.top_offenders:
            for o in r.top_offenders:
                asn_display = f"AS{o.asn}" if o.asn.isdigit() else o.asn
                offenders.add_row(str(o.count), o.ip, o.country, asn_display, o.asn_org)
        else:
            offenders.add_row("0", "(none)", "", "", "")

        # Active jails line
        jails_line.update(", ".join(r.jail_list) if r.jail_list else "(no jails found)")

        # Bans per jail table
        if r.bans_per_jail:
            for jail, c in r.bans_per_jail:
                bans_per_jail.add_row(jail, str(c))
        else:
            bans_per_jail.add_row("(none)", "0")

        # Last bans table: render the normalized history without parsing raw text.
        if r.last_10_bans:
            for event in r.last_10_bans:
                last_bans.add_row(
                    event.timestamp.strftime("%Y-%m-%d"),
                    event.timestamp.strftime("%H:%M:%S"), event.jail, event.ip,
                )
        else:
            last_bans.add_row("", "", "", "(no ban lines in selected period)")


def main(argv=None):
    """Keep the default dashboard launch and dispatch explicit GeoIP commands."""
    args = sys.argv[1:] if argv is None else argv
    if args:
        from offenders_geoip_cli import main as geoip_main
        if args[0] == "geoip":
            return geoip_main(args[1:])
        print("Usage: offenders [geoip {status,update,auto on|off}]", file=sys.stderr)
        return 2
    OffendersApp().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
