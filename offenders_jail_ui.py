"""Current jail detail rendered exclusively from successful dashboard reports."""

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Static

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
    return Text("\n".join(lines))


class JailDetailScreen(Screen[None]):
    """Retain jail identity and navigation while accepting successful snapshots."""

    BINDINGS = [("escape", "dismiss", "Back"), ("q", "dismiss", "Back")]

    def __init__(self, jail: str, report: Report) -> None:
        super().__init__()
        self.jail = jail
        self.report = report

    def compose(self) -> ComposeResult:
        """Mount the scroll surface once so refresh does not replace navigation."""
        with VerticalScroll():
            yield Static(jail_details(self.jail, self.report), id="jail-details")
        yield Footer()

    def update_report(self, report: Report) -> None:
        """Refresh literal status in place without changing focus or scroll."""
        self.report = report
        self.query_one("#jail-details", Static).update(jail_details(self.jail, report))
