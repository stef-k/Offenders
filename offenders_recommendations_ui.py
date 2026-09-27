"""Manual coverage presentation; acquisition stays off-loop and policy stays in #33."""
from collections import Counter
from datetime import timezone

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.worker import get_current_worker
from textual.widgets import DataTable, Footer, Static

from offenders_validation_ui import ValidationScreen
from offenders_host import discover_host_inventory
from offenders_sources import discover_log_sources
from offenders_coverage import discover_coverage
from offenders_evidence import EvidenceCollector
from offenders_patterns import analyze_patterns
from offenders_findings import FindingDecision, FindingInventory, build_findings

# Presentation labels describe existing decisions without re-evaluating policy.
REVIEW_LABELS = {
    "existing_disabled_candidate": "Review existing disabled jail/filter",
    "enabled_tuning_question": "Review enabled jail/filter coverage",
    "custom_gap_candidate": "Investigate custom jail/filter candidate",
}
SUPPRESSION_LABELS = {
    "below_recurrence_threshold": "Below recurrence threshold",
    "non_global_only": "Non-global-only",
    "inactive_service": "Inactive service",
    "enabled_relevant_below_tuning_threshold": "Relevant enabled coverage below tuning threshold",
    "insufficient_evidence": "Insufficient evidence",
}
CAVEATS = {
    "existing_disabled_candidate": (
        "Filter suitability is not yet established. This candidate is unvalidated; "
        "press v to inspect bounded validation evidence."),
    "enabled_tuning_question": (
        "This does not prove the jail failed or that a ban should already have happened. "
        "Pre-ban failures, multiple clients and ordinary jail timing/settings can explain "
        "visible records. Later validation/review may be useful."),
    "custom_gap_candidate": (
        "No custom configuration has been generated; no regex has been validated. "
        "An existing suitable definition remains preferable if later found."),
}


def run_analysis() -> FindingInventory:
    """Acquire one source snapshot and return the existing policy inventory unchanged."""
    host = discover_host_inventory()
    sources = discover_log_sources(host)
    coverage = discover_coverage(sources)
    evidence = EvidenceCollector().collect(sources)
    patterns = analyze_patterns(evidence)
    return build_findings(patterns, coverage)


def format_time(value, basis: str) -> str:
    """Preserve the upstream time domain without inventing offsets or event times."""
    if basis == "unknown":
        return "unknown"
    if value is None:
        return "unavailable"
    if basis == "local_wall":
        return f"{value.isoformat(sep=' ')} (local wall clock)"
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def finding_detail(decision: FindingDecision) -> str:
    """Render only the selected object's bounded facts and literal retained examples."""
    group = decision.group
    lines = [REVIEW_LABELS[decision.classification], decision.reason, CAVEATS[decision.classification],
             "", f"Service family: {group.family}", f"Service states: {', '.join(decision.service_states)}",
             f"Source kind: {group.source_kind}", f"Canonical source: {group.source_identity}",
             "", f"Pattern: {group.pattern_kind}", f"Signature: {group.signature}",
             f"Recognized records: {group.event_count}",
             f"Distinct source IPs: {group.distinct_source_ip_count}",
             f"Global source IPs: {group.global_source_ip_count}",
             f"Non-global source IPs: {group.non_global_source_ip_count}",
             f"First seen: {format_time(group.first_seen, group.timestamp_basis)}",
             f"Last seen: {format_time(group.last_seen, group.timestamp_basis)}",
             f"Timestamp basis: {group.timestamp_basis}"]
    if group.timestamp_basis in ("local_wall", "unknown"):
        lines.append("The exact UTC lookback could not be enforced.")
    lines.extend(("", "Current coverage (source monitoring does not establish filter success):"))
    for label, matches in (("Relevant running jail", decision.running_filters),
                           ("Retained disabled jail", decision.disabled_candidates)):
        lines.append(f"{label}: " + ("; ".join(f"{m.name} / filter {m.filter_stem}" for m in matches) or "none established"))
    lines.append("Coverage classifications: " + ", ".join(dict.fromkeys(
        target.classification for target in decision.coverage_targets)))
    lines.extend(("", "Representative examples:", *group.examples[:3], "", "Limitations:"))
    lines.extend(decision.limitations or ("None reported",))
    return "\n".join(lines)


def analysis_summary(inventory: FindingInventory) -> str:
    """Count supplied decisions and source states, never reinterpret recommendation gates."""
    patterns = inventory.pattern_inventory
    evidence = patterns.evidence_snapshot
    counts = Counter(row.classification for row in inventory.decisions)
    lines = [f"{len(inventory.findings)} candidate findings" if inventory.findings else "No recommendation",
             f"Analysis snapshot: {format_time(evidence.collected_at, 'utc')}",
             f"Requested window: {format_time(evidence.requested_since, 'utc')} — "
             f"{format_time(evidence.collected_at, 'utc')}",
             "Suppressed / insufficient: " + "; ".join(
                 f"{label}: {counts[key]}" for key, label in SUPPRESSION_LABELS.items())]
    if not patterns.groups:
        states = Counter(row.state for row in patterns.analyses)
        lines.append("No supported pattern was recognized.")
        lines.append(f"Supported sources analyzed: {states['analyzed'] + states['partial']}; "
                     f"unsupported source families: {states['unsupported']}; "
                     f"unavailable/skipped/partial source analyses: "
                     f"{sum(count for state, count in states.items() if state not in ('analyzed', 'unsupported'))}.")
        if not patterns.analyses:
            lines.append("No source/family analysis was available; evidence completeness is unknown.")
    partial = any(row.state != "analyzed" or row.limitations for row in patterns.analyses)
    if partial or evidence.truncated or evidence.limitations:
        lines.append("Evidence completeness: partial or limited; source notes and decision limitations apply.")
    return "\n".join(lines)


def bounded_error(error: Exception) -> str:
    """Normalize terminal controls and whitespace before limiting exception display."""
    printable = "".join(char if char.isprintable() else " " for char in str(error))
    return " ".join(printable.split())[:240]


class RecommendationsScreen(Screen):
    """Own one manual worker and its immutable result until this screen closes."""

    BINDINGS = [("v", "validate", "Validate"), ("escape", "close", "Close"), ("q", "close", "Close")]
    DEFAULT_CSS = """
    RecommendationsScreen { layout: vertical; }
    #coverage-summary { height: auto; max-height: 12; }
    #coverage-findings { height: 1fr; min-height: 5; }
    #coverage-scroll { height: 2fr; }
    """

    def __init__(self):
        super().__init__()
        self.inventory: FindingInventory | None = None
        self.decisions: dict[str, FindingDecision] = {}
        self._delivery_closed = False

    def compose(self) -> ComposeResult:
        """Keep long selected evidence independently scrollable."""
        yield Static("Coverage / Recommendations\nAnalyzing coverage…", id="coverage-summary", markup=False)
        yield DataTable(id="coverage-findings", cursor_type="row")
        with VerticalScroll(id="coverage-scroll"):
            yield Static("", id="coverage-detail", markup=False)
        yield Footer()

    def on_mount(self) -> None:
        """Opening is the only trigger; no rerun action or timer is installed."""
        table = self.query_one(DataTable)
        table.add_columns("Review type", "Service", "Pattern", "Events", "Global IPs", "Source")
        table.focus()
        self._analyze()

    @work(thread=True)
    def _analyze(self) -> None:
        """Run all acquisition off-loop and discard cancelled delivery."""
        worker = get_current_worker()
        app = self.app
        try:
            inventory, error = run_analysis(), None
        except Exception as exc:
            inventory, error = None, bounded_error(exc)
        if not worker.is_cancelled:
            app.call_from_thread(self._complete, inventory, error)

    def _complete(self, inventory: FindingInventory | None, error: str | None) -> None:
        """A closed/unmounted view cannot publish into a later screen."""
        if self._delivery_closed or not self.is_mounted:
            return
        summary = self.query_one("#coverage-summary", Static)
        if error is not None:
            summary.update(Text(f"Coverage / Recommendations\nAnalysis unavailable\n{error}"))
            return
        self.inventory = inventory
        summary.update(Text("Coverage / Recommendations\n" + analysis_summary(inventory)))
        table = self.query_one(DataTable)
        for index, decision in enumerate(inventory.findings):
            key = str(index)
            self.decisions[key] = decision
            group = decision.group
            table.add_row(*(Text(str(cell)) for cell in (
                REVIEW_LABELS[decision.classification], group.family, group.signature,
                group.event_count, group.global_source_ip_count, group.source_identity)), key=key)
        if inventory.findings:
            self._show_detail("0")

    @on(DataTable.RowHighlighted, "#coverage-findings")
    def highlight_finding(self, event: DataTable.RowHighlighted) -> None:
        """Use stable row identity, never parse formatted cells back into policy."""
        self._show_detail(event.row_key.value)

    def _show_detail(self, key: str) -> None:
        """Replace the selected detail without caching other rendered evidence."""
        if key in self.decisions:
            self.query_one("#coverage-detail", Static).update(Text(finding_detail(self.decisions[key])))
            self.query_one("#coverage-scroll", VerticalScroll).scroll_home(animate=False)

    def action_validate(self) -> None:
        """Open explicit validation using this screen's exact retained finding."""
        if self.inventory is None or not self.inventory.findings:
            return
        decision = self.inventory.findings[self.query_one(DataTable).cursor_row]
        self.app.push_screen(ValidationScreen(self.inventory, decision))

    def action_close(self) -> None:
        """Stop result delivery immediately, before asynchronous removal finishes."""
        self._delivery_closed = True
        self.workers.cancel_node(self)
        self.dismiss()

    def on_unmount(self) -> None:
        """Also guard removal paths other than the local close bindings."""
        self._delivery_closed = True
