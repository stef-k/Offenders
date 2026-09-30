"""One acquisition-free Help screen with curated runtime-derived context actions."""
from dataclasses import dataclass

from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Static

from offenders_activity import OffendersFooter
from offenders_candidate_ui import CustomCandidateScreen
from offenders_export_ui import ExportScreen
from offenders_enforcement_ui import EnforcementScreen
from offenders_geoip_ui import GeoIPScreen
from offenders_help_content import product_guide
from offenders_ip_ui import CommandOutputModal, IPInspectorScreen
from offenders_jail_ui import JailDetailScreen
from offenders_recommendations_ui import RecommendationsScreen
from offenders_validation_ui import ValidationScreen


@dataclass(frozen=True)
class HelpContext:
    """Curate action identities/order, never a second runtime key map."""

    name: str
    actions: tuple[str, ...]
    prose: str
    enter: str = ""


DASHBOARD = HelpContext(
    "Dashboard", ("refresh", "period", "filter", "view", "enter", "export", "geoip",
                  "coverage", "enforcement", "registration", "rdns", "copy_selection", "toggle_cursor", "quit"),
    "The dashboard combines historical activity with current jail state. Reports refresh "
    "automatically; a failed refresh preserves the last successful snapshot.",
    "Open selected real IP or active jail (where applicable)",
)
# Enter supplements correspond to DataTable selection events, not screen bindings.
CONTEXTS = {
    EnforcementScreen: HelpContext(
        "Enforcement", ("recheck", "copy_selection", "toggle_cursor", "close"),
        "Opening runs one read-only check; Recheck is available when idle. Each action/IP retains "
        "its own outcome. Old evidence is cleared on recheck. Direct rule/object observation "
        "is not packet or reachability proof; this workflow never joins report refresh or CSV Export."),
    JailDetailScreen: HelpContext(
        "Jail detail", ("refresh", "period", "expand_history", "copy_selection", "toggle_cursor", "enter", "dismiss"),
        "Live jail counters/membership and selected-period historical bans are different facts. "
        "Expanding history uses retained events without reacquiring data.", "Open selected historical IP"),
    IPInspectorScreen: HelpContext(
        "IP inspector", ("refresh", "period", "registration", "rdns", "copy_selection", "toggle_cursor", "enter", "dismiss"),
        "The inspector combines committed historical facts, current membership and local GeoIP projection. "
        "Registration/RDNS are explicit separate network actions.", "Open selected listed jail"),
    ExportScreen: HelpContext(
        "Export", ("export", "copy_path", "close"),
        "TUI Export uses the committed report captured when Export was opened, with no new report acquisition. "
        "Dashboard filter and summary mode do not change contents; the exact successful path remains visible."),
    GeoIPScreen: HelpContext(
        "GeoIP diagnostics", ("update_now", "toggle_auto", "dismiss"),
        "GeoIP is optional local Country/ASN enrichment using app-managed generations. "
        "Updates validate before activation; automatic updates are opt-in."),
    RecommendationsScreen: HelpContext(
        "Coverage / Recommendations", ("coverage_period", "validate", "app.copy_selection", "app.toggle_cursor", "close"),
        "Coverage is manual and independent of the dashboard period. It opens with a 7d window; "
        "p switches 7d/24h when idle. Bounded file tails and one plain rotation can provide only "
        "partial history; compressed/deeper rotations are not read. The decision table includes "
        "candidates and suppressed/insufficient rows, which explain evidence and are not recommendations. "
        "Validate is available only for a selected candidate. "
        "Findings do not prove maliciousness, reachability or filter suitability."),
    ValidationScreen: HelpContext(
        "Existing-filter validation", ("validate", "copy_selection", "toggle_cursor", "enter", "close"),
        "Validation is bounded review evidence against retained samples. "
        "It does not enable/reload/change Fail2Ban or prove operational suitability.", "Validate selected target"),
    CustomCandidateScreen: HelpContext(
        "Custom candidate", ("generate", "copy_candidate", "close"),
        "Fixed-template candidates are validated for review and remain disabled/copy-only. "
        "They are never installed or enabled automatically."),
}
# Conditions describe supported actions without claiming they are executable now.
CONDITIONS = {
    "copy_selection": "when a table is focused with a valid selection",
    "toggle_cursor": "when a table is focused",
    "copy_path": "available after successful export, while no export is running",
    "copy_candidate": "only when a reviewable validated result is exposed, while generation is idle",
    "copy_output": "when result output exists",
}


def help_context(app) -> HelpContext | None:
    """Recognize only product screens; Help and framework screens are excluded."""
    screen = app.screen
    if screen is app.default_screen:
        return DASHBOARD
    if isinstance(screen, CommandOutputModal):
        name = "Registration (RDAP)" if screen.tool == "registration" else "RDNS (PTR)"
        return HelpContext(name, ("copy_output", "dismiss"),
                           "This explicit/on-demand lookup returns bounded factual output. "
                           "Neither Registration nor PTR data is a reputation assessment.")
    return CONTEXTS.get(type(screen))


def context_text(context: HelpContext, bindings, inherited_bindings=()) -> str:
    """Derive local and inherited controls, keeping local key ownership authoritative."""
    runtime = list(Binding.make_bindings(bindings))
    local_keys = {binding.key for binding in runtime}
    runtime.extend(binding for binding in Binding.make_bindings(inherited_bindings)
                   if binding.key not in local_keys)
    lines = [f"Current screen: {context.name}", "", "What you can do here"]
    for action in context.actions:
        if action == "enter":
            lines.append(f"  Enter  {context.enter}")
            continue
        matches = [binding for binding in runtime if binding.action == action]
        keys = "/".join(binding.key_display or ("Esc" if binding.key == "escape" else binding.key)
                        for binding in matches)
        description = " / ".join(dict.fromkeys(binding.description for binding in matches))
        condition = CONDITIONS.get(action.removeprefix("app."))
        qualifier = f" ({condition})" if condition else ""
        lines.append(f"  {keys}  {description}{qualifier}")
    return "\n".join((*lines, "", context.prose))


class HelpScreen(ModalScreen):
    """Opaque full-screen modal: scroll and close without invoking product actions."""

    BINDINGS = [("escape", "dismiss", "Close"), ("q", "dismiss", "Close")]
    DEFAULT_CSS = """
    HelpScreen { background: $surface; layout: vertical; }
    HelpScreen #help-scroll { height: 1fr; padding: 0 1; }
    HelpScreen Static { height: auto; margin-bottom: 1; }
    """

    def __init__(self, context: str, project_info: str):
        super().__init__()
        self.context = context
        self.project_info = project_info

    def compose(self):
        """Render literal local text; no workers, file reads or URL handling."""
        with VerticalScroll(id="help-scroll"):
            yield Static(self.context, id="help-context", markup=False)
            yield Static("Scroll: ↑/↓, PageUp/PageDown, Home/End. Close: Esc/q.", markup=False)
            yield Static(product_guide(self.app.BINDINGS), id="help-guide", markup=False)
            yield Static(self.project_info, id="help-project", markup=False)
        yield OffendersFooter()

    def on_mount(self):
        """Start context at the top with keyboard scrolling ready."""
        self.query_one("#help-scroll", VerticalScroll).focus()
