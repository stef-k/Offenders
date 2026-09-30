"""Manual coverage presentation; acquisition stays off-loop and offenders_findings owns policy."""
from collections import Counter
from datetime import timedelta, timezone

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import ModalScreen
from textual.worker import Worker, get_current_worker
from textual.widgets import DataTable, Static

from offenders_selection import current_row_key, event_row_key
from offenders_activity import OffendersFooter
from offenders_help_content import HELP_BINDING
from offenders_validation_ui import ValidationScreen
from offenders_candidate_ui import CustomCandidateScreen
from offenders_host import discover_host_inventory
from offenders_sources import discover_log_sources
from offenders_coverage import discover_coverage
from offenders_evidence import EvidenceCollector
from offenders_patterns import analyze_patterns
from offenders_findings import CANDIDATES, FindingDecision, FindingInventory, build_findings

# Coverage requests raw evidence independently of the dashboard's ban history.
COVERAGE_PERIODS = {"7d": timedelta(days=7), "24h": timedelta(hours=24)}
DEFAULT_COVERAGE_PERIOD = "7d"

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


def run_analysis(lookback: timedelta) -> FindingInventory:
    """Acquire one source snapshot and return the existing policy inventory unchanged."""
    host = discover_host_inventory()
    sources = discover_log_sources(host)
    coverage = discover_coverage(sources)
    evidence = EvidenceCollector().collect(sources, lookback=lookback)
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
    candidate = decision.classification in CANDIDATES
    label = REVIEW_LABELS[decision.classification] if candidate else SUPPRESSION_LABELS[decision.classification]
    caveat = CAVEATS[decision.classification] if candidate else "Suppressed / not a recommendation"
    lines = [label, decision.reason, caveat,
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


class RecommendationsScreen(ModalScreen):
    """Own one manual worker and its immutable result until this screen closes."""

    BINDINGS = [HELP_BINDING, ("p", "coverage_period", "Coverage Period"),
                ("v", "validate", "Validate"), ("c", "app.copy_selection", "Copy"),
                ("x", "app.copy_selection", "Copy"), ("t", "app.toggle_cursor", "Row/Cell"),
                ("escape", "close", "Close"), ("q", "close", "Close")]
    DEFAULT_CSS = """
    RecommendationsScreen { background: $surface; layout: vertical; }
    #coverage-summary { height: auto; max-height: 12; }
    #coverage-findings { height: 1fr; min-height: 5; }
    #coverage-scroll { height: 2fr; }
    """

    def __init__(self):
        """Keep the committed window and worker ownership local to this opening."""
        super().__init__()
        self.coverage_period = DEFAULT_COVERAGE_PERIOD
        self.inventory: FindingInventory | None = None
        self.decisions: dict[str, FindingDecision] = {}
        self._analysis_worker: Worker | None = None
        self._generation = 0
        self._delivery_closed = False

    def compose(self) -> ComposeResult:
        """Keep long selected evidence independently scrollable."""
        yield Static("Coverage / Recommendations\nAnalyzing coverage…", id="coverage-summary", markup=False)
        yield DataTable(id="coverage-findings", cursor_type="row")
        with VerticalScroll(id="coverage-scroll"):
            yield Static("", id="coverage-detail", markup=False)
        yield OffendersFooter()

    def on_mount(self) -> None:
        """Opening requests the default horizon; no analysis timer is installed."""
        table = self.query_one(DataTable)
        table.add_columns("Disposition", "Service", "Pattern", "Events", "Global IPs", "Source")
        table.focus()
        self._start_analysis(DEFAULT_COVERAGE_PERIOD)

    def action_coverage_period(self) -> None:
        """Request only the next Coverage horizon, without changing committed state."""
        periods = tuple(COVERAGE_PERIODS)
        target = periods[(periods.index(self.coverage_period) + 1) % len(periods)]
        self._start_analysis(target)

    def _start_analysis(self, period: str) -> None:
        """Exclude overlapping workers and remove old evidence before acquisition."""
        if self._delivery_closed:
            return
        if self._analysis_worker is not None and not self._analysis_worker.is_finished:
            self.app.notify("Analysis already in progress", timeout=2.0)
            return
        self._generation += 1
        self.inventory = None
        self.decisions.clear()
        self.query_one(DataTable).clear()
        self.query_one("#coverage-detail", Static).update("")
        self.query_one("#coverage-summary", Static).update(
            f"Coverage / Recommendations\nRequested Coverage window: {period} "
            "(independent of dashboard period)\nAnalyzing coverage…")
        self.refresh_bindings()
        self._analysis_worker = self._analyze(period)

    @work(thread=True, name="activity:Analyzing coverage…")
    def _analyze(self, period: str) -> None:
        """Run all acquisition off-loop and discard cancelled delivery."""
        worker = get_current_worker()
        app = self.app
        try:
            inventory, error = run_analysis(COVERAGE_PERIODS[period]), None
        except Exception as exc:
            inventory, error = None, bounded_error(exc)
        if not worker.is_cancelled:
            app.call_from_thread(self._complete, inventory, error, period, worker)

    def _complete(self, inventory: FindingInventory | None, error: str | None,
                  period: str, worker=None) -> None:
        """A closed/unmounted view cannot publish into a later screen."""
        if self._delivery_closed or not self.is_mounted or (worker is not None and (
                worker is not self._analysis_worker or worker.is_cancelled)):
            return
        summary = self.query_one("#coverage-summary", Static)
        if error is not None:
            summary.update(Text(f"Coverage / Recommendations\nRequested Coverage window: {period} "
                                f"(independent of dashboard period)\nAnalysis unavailable\n{error}"))
            return
        self.coverage_period = period
        self.inventory = inventory
        summary.update(Text(f"Coverage / Recommendations\nCoverage window: {period} "
                            "(independent of dashboard period)\n" + analysis_summary(inventory)))
        table = self.query_one(DataTable)
        for index, decision in enumerate(inventory.decisions):
            key = f"{self._generation}:{index}"
            self.decisions[key] = decision
            group = decision.group
            table.add_row(*(Text(str(cell)) for cell in (
                (REVIEW_LABELS | SUPPRESSION_LABELS)[decision.classification], group.family, group.signature,
                group.event_count, group.global_source_ip_count, group.source_identity)), key=key)
        key = current_row_key(table)
        if key is not None:
            self._show_detail(key.value)
        self.refresh_bindings()

    @on(DataTable.RowHighlighted, "#coverage-findings")
    @on(DataTable.CellHighlighted, "#coverage-findings")
    def highlight_finding(self, event: DataTable.RowHighlighted | DataTable.CellHighlighted) -> None:
        """Use stable row identity, never parse formatted cells back into policy."""
        key = event_row_key(event)
        if key is not None and not self._delivery_closed:
            self._show_detail(key.value)
        self.refresh_bindings()

    def _show_detail(self, key: str) -> None:
        """Replace the selected detail without caching other rendered evidence."""
        if key in self.decisions:
            self.query_one("#coverage-detail", Static).update(Text(finding_detail(self.decisions[key])))
            self.query_one("#coverage-scroll", VerticalScroll).scroll_home(animate=False)

    def _selected_candidate(self) -> FindingDecision | None:
        """Accept only a current row whose existing policy class allows validation."""
        if self._delivery_closed or self.inventory is None:
            return None
        key = current_row_key(self.query_one(DataTable))
        decision = self.decisions.get(key.value) if key is not None else None
        return decision if decision is not None and decision.classification in CANDIDATES else None

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        """Hide Validate for empty, stale and suppressed selections."""
        if action == "validate":
            return self._selected_candidate() is not None
        return super().check_action(action, parameters)

    def action_validate(self) -> None:
        """Open candidate-only validation using the exact retained decision."""
        decision = self._selected_candidate()
        if decision is None:
            return
        screen = CustomCandidateScreen if decision.classification == "custom_gap_candidate" else ValidationScreen
        self.app.push_screen(screen(self.inventory, decision))

    def action_close(self) -> None:
        """Stop result delivery immediately, before asynchronous removal finishes."""
        self._delivery_closed = True
        self.workers.cancel_node(self)
        self.dismiss()

    def on_unmount(self) -> None:
        """Also guard removal paths other than the local close bindings."""
        self._delivery_closed = True
        self.workers.cancel_node(self)
