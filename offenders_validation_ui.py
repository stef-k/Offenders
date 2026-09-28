"""Explicit single-target validation presentation over the retained Coverage snapshot."""
from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Static
from textual.worker import get_current_worker

from offenders_validation import FilterValidation, eligible_targets, validate_existing

# Aggregate context evidence cannot establish a false-positive rate or suitability.
INTERPRETATION = (
    "Target matches show that Fail2Ban's filter matched lines in this bounded target sample. "
    "Target misses and ignored lines are concrete review evidence. "
    "Context is same-source background evidence: context matches are not automatically false positives. "
    "Zero context matches do not establish low false-positive risk. "
    "Successful validation does not prove the filter is safe or suitable for enabling. "
    "Samples are bounded and may be partial. Tested lines may differ from logical records."
)
NO_TARGET = (
    "No existing filter target is available. Prospective custom filter validation "
    "is provided to the later custom-candidate workflow."
)


def validation_detail(result: FilterValidation) -> str:
    """Present retained counters literally without exposing expired temp arguments."""
    lines = [f"Validation: {result.state}",
             f"Jail: {result.jail_name or 'none'} / filter: {result.filter_stem or 'custom'}"]
    if result.target_kind == "existing":
        lines.append(f"Filter argument: {result.filter_argument or 'unavailable'}")
        lines.append(f"Effective options reproduced: {result.effective_options_reproduced}")
    for label, sample in (("Target", result.target), ("Context", result.context)):
        lines.extend(("", label + " sample:"))
        if sample is None:
            lines.append("Unavailable; no context counts")
            continue
        lines.append(f"Logical records: {sample.selected_records} selected / {sample.available_records} available; "
                     f"{sample.written_bytes} UTF-8 bytes; truncated: {sample.truncated}")
        if sample.tested_lines is not None:
            lines.append(f"Tested lines: {sample.tested_lines}; matched: {sample.matched_lines}; "
                         f"missed: {sample.missed_lines}; ignored: {sample.ignored_lines}")
        else:
            lines.append("Counts unavailable")
        if sample.failure:
            lines.append(f"Command unavailable: {sample.failure.value}")
        if sample.detail:
            lines.append(sample.detail)
        lines.extend((*sample.limitations, "Input examples:", *sample.examples))
    lines.extend(("", "Limitations:", *result.limitations, "", INTERPRETATION))
    return "\n".join(lines)


class ValidationScreen(Screen):
    """Own one off-loop validation at a time; closing only cancels result delivery."""

    BINDINGS = [("v", "validate", "Validate selected"), ("escape", "close", "Close"), ("q", "close", "Close")]
    DEFAULT_CSS = """
    ValidationScreen { layout: vertical; }
    #validation-targets { height: auto; max-height: 10; }
    #validation-scroll { height: 1fr; }
    """

    def __init__(self, inventory, decision):
        super().__init__()
        self.inventory = inventory
        self.decision = decision
        self.targets = eligible_targets(inventory, decision)
        self.result: FilterValidation | None = None
        self._active = False
        self._delivery_closed = False

    def compose(self) -> ComposeResult:
        """List eligible targets without starting a process on mount/highlight."""
        yield Static("Filter validation — select one target, then press v or Enter", markup=False)
        yield DataTable(id="validation-targets", cursor_type="row")
        with VerticalScroll(id="validation-scroll"):
            yield Static("Ready to validate" if self.targets else NO_TARGET, id="validation-detail", markup=False)
        yield Footer()

    def on_mount(self) -> None:
        """Preserve the exact target tuple rather than reconstructing cell values."""
        table = self.query_one(DataTable)
        table.add_columns("Jail", "Filter")
        for index, target in enumerate(self.targets):
            table.add_row(Text(target.name), Text(target.filter_stem), key=str(index))
        table.focus()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """An explicit row selection starts only that target's validation."""
        self.action_validate()

    def action_validate(self) -> None:
        """Reject repeated requests while the current bounded operation is active."""
        if self._active or self._delivery_closed or not self.targets:
            return
        target = self.targets[self.query_one(DataTable).cursor_row]
        self._active = True
        self.query_one("#validation-detail", Static).update(Text(f"Validating… {target.name} / {target.filter_stem}"))
        self._validate(target)

    @work(thread=True, name="activity:Validating…")
    def _validate(self, target) -> None:
        """Let backend cleanup finish even when this worker's delivery is cancelled."""
        worker, app = get_current_worker(), self.app
        try:
            result = validate_existing(self.inventory, self.decision, target)
            error = None
        except Exception:
            result, error = None, "Validation unavailable: unexpected validation error"
        if not worker.is_cancelled:
            app.call_from_thread(self._complete, result, error)

    def _complete(self, result, error) -> None:
        """Discard delivery to removed screens without touching newer views."""
        if self._delivery_closed or not self.is_mounted:
            return
        self._active = False
        self.result = result
        self.query_one("#validation-detail", Static).update(Text(error or validation_detail(result)))
        self.query_one("#validation-scroll", VerticalScroll).scroll_home(animate=False)

    def action_close(self) -> None:
        """Immediately block stale UI delivery; the bounded backend still owns cleanup."""
        self._delivery_closed = True
        self.workers.cancel_node(self)
        self.dismiss()

    def on_unmount(self) -> None:
        """Cover external screen removal as well as local close bindings."""
        self._delivery_closed = True
