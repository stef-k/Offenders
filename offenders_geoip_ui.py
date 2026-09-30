"""Focused GeoIP diagnostics and background lifecycle actions for the TUI."""
from __future__ import annotations

from pathlib import Path
import time

from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Static
from textual.worker import get_current_worker

from offenders_activity import OffendersFooter
from offenders_help_content import HELP_BINDING
from offenders_geoip import geoip, resolve_data_root
from offenders_geoip_update import UpdateError, read_state, set_auto, update

STALE_SECONDS = 62 * 86400  # Local age warns; it never disables usable lookups.


def status_line(health, now=None):
    """Summarize subsystem health independently of individual unmapped IPs."""
    now = time.time() if now is None else now
    warnings = []
    for kind, database in health.items():
        if database.state != "healthy":
            warnings.append(f"{kind.title()} unavailable")
        elif database.mtime_ns is not None and now - database.mtime_ns / 1e9 > STALE_SECONDS:
            warnings.append(f"{kind.title()} stale (usable)")
    return "GeoIP: " + "; ".join(warnings) + " — g: details" if warnings else ""


def guidance(database):
    """Suggest only actions supported by the shared reader and updater."""
    if not database.reader_available:
        return "Repair the application Python environment (MMDB reader unavailable)."
    if database.state == "unreadable":
        return "Inspect user-owned path permissions; Update now may replace writable data."
    if database.state != "healthy":
        return "Use Update now to stage a fresh generation."
    if database.mtime_ns is not None and time.time() - database.mtime_ns / 1e9 > STALE_SECONDS:
        return "Use Update now or enable automatic updates for stale local data."
    return "Database healthy."


def diagnostics(health, root, state, feedback):
    """Render authoritative snapshots as literal text, without inspecting files."""
    lines = ["GeoIP diagnostics", f"App-managed root: {root}",
             f"Stable pair reference: {root / 'current'}",
             f"Automatic updates: {'on' if state.get('auto') is True else 'off'}",
             f"Latest update outcome: {state.get('outcome', 'never checked')}",
             f"Last check (UTC epoch): {state.get('last_check', 'never')}"]
    for kind, database in health.items():
        lines.extend(("", f"{kind.title()} database: {database.state}",
                      f"  Current path: {database.path}",
                      f"  Resolved target: {database.resolved_path or 'unknown'}",
                      f"  Exists: {database.exists}; readable: {database.readable}; valid: {database.metadata_valid}",
                      f"  Python MMDB reader: {'available' if database.reader_available else 'unavailable'}"))
        if database.resolved_path:
            parent = Path(database.resolved_path).parent
            if parent.parent == root.absolute() / "generations":
                lines.append(f"  Active generation: {parent.name}")
        if database.mtime_ns is not None:
            days = max(0, (time.time() - database.mtime_ns / 1e9) / 86400)
            lines.append(f"  Observed local file age: {days:.1f} days" +
                         (" (stale warning; still usable)"
                          if database.state == "healthy" and days > 62 else ""))
        if database.detail:
            lines.append(f"  Detail: {bounded(database.detail)}")
        lines.append(guidance(database))
    lines.extend(("", feedback, "u: Update now   a: Toggle automatic updates   Esc/q: Close"))
    return Text("\n".join(lines))


def bounded(error):
    """Keep lifecycle failures concise and safe for terminal presentation."""
    return "".join(c for c in " ".join(str(error).split()) if c.isprintable())[:240]


class GeoIPStatus(Static):
    """Own app-lifetime workers so closing diagnostics cannot cancel activation."""

    DEFAULT_CSS = "GeoIPStatus { height: 1; }"

    def __init__(self, refresh_report):
        super().__init__("", id="geoip-status")
        self.refresh_report = refresh_report
        self.health = {}
        self.state = {}
        self.feedback = ""
        self.root = resolve_data_root()

    def on_mount(self):
        """Read local health and run the sole mount-triggered policy check."""
        self._startup()

    @work(thread=True, name="activity:Checking GeoIP…")
    def _startup(self):
        """Disabled policy reads are side-effect free, including first launch."""
        self.app.call_from_thread(self.set_health, geoip.refresh())
        try:
            state = read_state(self.root)
            self.app.call_from_thread(self._set_state, state)
            if state.get("auto") is True:
                self._perform_update(automatic=True)
        except (UpdateError, OSError) as error:
            self.app.call_from_thread(self._feedback, bounded(error))

    def set_health(self, health):
        """Accept report or post-activation database facts without touching freshness."""
        self.health = health
        line = status_line(health)
        self.display = bool(line)
        self.update(Text(line))
        self._redraw()

    def _set_state(self, state):
        """Publish a shared-policy snapshot on the event loop."""
        self.state = state
        self._redraw()

    def _feedback(self, message):
        """Display errors separately from database health, preserving usable data."""
        self.feedback = message
        self._redraw()

    def _redraw(self):
        """Update an open diagnostics view without requiring it to stay mounted."""
        screen = self.app.screen
        if isinstance(screen, GeoIPScreen):
            screen.render_details()

    @work(thread=True, name="activity:Updating GeoIP…")
    def update_now(self):
        """Each explicit action uses the shared nonblocking writer lock."""
        self._perform_update(automatic=False)

    def _perform_update(self, *, automatic):
        """Delegate locking, due policy, download and activation to offenders_geoip_update."""
        self.app.call_from_thread(self.app.workers.label, get_current_worker(), "Updating GeoIP…")
        self.app.call_from_thread(self._feedback, "Updating GeoIP…")
        try:
            result = update(self.root, automatic=automatic)
            if result is None:
                self.app.call_from_thread(self._feedback, "GeoIP check complete; no update needed.")
            else:
                health = geoip.refresh()
                self.app.call_from_thread(self._activated, health, result)
        except (UpdateError, OSError) as error:
            self.app.call_from_thread(self._feedback, bounded(error))
        finally:
            try:
                state = read_state(self.root)
                self.app.call_from_thread(self._set_state, state)
            except UpdateError as error:
                self.app.call_from_thread(self._feedback, bounded(error))

    def _activated(self, health, result):
        """Request a normal single-flight refresh; a collision stays skipped."""
        self.set_health(health)
        self._feedback(f"Activated {bounded(result)}")
        self.refresh_report()

    @work(thread=True, name="activity:Saving GeoIP policy…")
    def toggle_auto(self):
        """Explicit policy changes persist without scheduling network work."""
        try:
            state = read_state(self.root)
            set_auto(state.get("auto") is not True, self.root)
            self.app.call_from_thread(self._set_state, read_state(self.root))
            self.app.call_from_thread(self._feedback, "Automatic policy saved (checked on next launch).")
        except (UpdateError, OSError) as error:
            self.app.call_from_thread(self._feedback, bounded(error))


class GeoIPScreen(ModalScreen):
    """Keyboard-first, scrollable diagnostics; no automatic first-run prompt."""

    BINDINGS = [HELP_BINDING, ("escape", "dismiss", "Close"), ("q", "dismiss", "Close"),
                ("u", "update_now", "Update now"), ("a", "toggle_auto", "Auto on/off")]

    def __init__(self, status):
        super().__init__()
        self.status = status

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Static(id="geoip-details")
        yield OffendersFooter()

    def on_mount(self):
        """Show the latest app-lifetime health and lifecycle snapshots."""
        self.render_details()

    def render_details(self):
        """Refresh literal diagnostic text after worker or report completion."""
        self.query_one("#geoip-details", Static).update(diagnostics(
            self.status.health, self.status.root, self.status.state, self.status.feedback))

    def action_update_now(self):
        """An explicit keypress consents to the rootless update."""
        if not self._already_working():
            self.status._feedback("Updating GeoIP…")
            self.status.update_now()

    def action_toggle_auto(self):
        """Persist the operator's explicit automatic-update preference."""
        if not self._already_working():
            self.status._feedback("Saving GeoIP policy…")
            self.status.toggle_auto()

    def _already_working(self):
        """Reject duplicate lifecycle keys before spawning another UI worker."""
        if any(worker.node is self.status and not worker.is_finished
               and not worker.is_cancelled for worker in self.app.workers):
            self.app.notify("GeoIP operation already in progress", timeout=2.0)
            return True
        return False
