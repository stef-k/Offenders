"""Explicit off-loop custom generation and literal, copy-only operator review."""
from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Static
from textual.worker import get_current_worker

from offenders_activity import OffendersFooter
from offenders_candidate import CustomCandidate, generate_candidate
from offenders_validation_ui import validation_detail

INITIAL = "Custom candidate — press v to generate and validate the fixed review template"
CAVEATS = (
    "Target sample matching does not prove safety. Context is not a known-clean corpus; "
    "context matches require operator review. Zero context matches do not prove low false-positive risk. "
    "Jail wiring was not activated or daemon-tested. Local inherited ban settings must be reviewed."
)


def copy_text(result: CustomCandidate) -> str:
    """Only reviewable results yield a combined block with exact validated bytes."""
    if result.state != "reviewable":
        return ""
    return (f"# Suggested filter.d/{result.name}.conf\n{result.filter_text}\n"
            f"# Suggested jail.d/{result.name}.local\n{result.jail_text}")


def candidate_detail(result: CustomCandidate) -> str:
    """Keep all limitations and sample evidence visible beside literal snippets."""
    group = result.decision.group
    title = ("Candidate for operator review — not installed or enabled" if result.state == "reviewable"
             else "Custom candidate withheld")
    lines = [title, result.reason, f"Service: {group.family}; signature: {group.signature}",
             f"Source: {result.source_kind or group.source_kind} {result.source_identity or group.source_identity}"]
    if result.validation:
        lines.extend((f"Filter SHA-256: {result.filter_sha256}; bytes: {result.filter_bytes}",
                      validation_detail(result.validation)))
    lines.extend(("Limitations:", *result.limitations, CAVEATS))
    if result.state == "reviewable":
        lines.extend(("", copy_text(result)))
    return "\n".join(lines)


class CustomCandidateScreen(Screen):
    """Own one explicit generation worker; never edit the retained Coverage snapshot."""

    BINDINGS = [("v", "generate", "Generate + validate"), ("c", "copy_candidate", "Copy candidate"),
                ("escape", "close", "Close"), ("q", "close", "Close")]
    DEFAULT_CSS = """
    CustomCandidateScreen { layout: vertical; }
    #candidate-scroll { height: 1fr; }
    """

    def __init__(self, inventory, decision):
        super().__init__()
        self.inventory = inventory
        self.decision = decision
        self.result: CustomCandidate | None = None
        self._active = False
        self._delivery_closed = False

    def compose(self) -> ComposeResult:
        """Mount without generating text or starting validation."""
        with VerticalScroll(id="candidate-scroll"):
            yield Static(INITIAL, id="candidate-detail", markup=False)
        yield OffendersFooter()

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        """Hide copy until a reviewable candidate is actually displayed."""
        if action == "copy_candidate":
            return bool(not self._delivery_closed and not self._active and self.result and self.result.state == "reviewable")
        return True

    def action_generate(self) -> None:
        """Exclude duplicate workers and clear any previously copyable output."""
        if self._active:
            self.app.notify("Candidate generation already in progress", timeout=2.0)
            return
        if self._delivery_closed:
            return
        self._active = True
        self.result = None
        self.refresh_bindings()
        self.query_one("#candidate-detail", Static).update(Text("Generating and validating candidate…"))
        self._generate()

    @work(thread=True, name="activity:Generating and validating candidate…")
    def _generate(self) -> None:
        """Backend retains responsibility for bounded command completion and cleanup."""
        worker, app = get_current_worker(), self.app
        try:
            result, error = generate_candidate(self.inventory, self.decision), None
        except Exception:
            result, error = None, "Custom candidate withheld: unexpected generation/validation error"
        if not worker.is_cancelled:
            app.call_from_thread(self._complete, result, error, worker)

    def _complete(self, result, error, worker=None) -> None:
        """Discard stale results after close or external removal."""
        if self._delivery_closed or not self.is_mounted or (worker is not None and worker.is_cancelled):
            return
        self._active = False
        self.result = result
        self.query_one("#candidate-detail", Static).update(Text(error or candidate_detail(result)))
        self.query_one("#candidate-scroll", VerticalScroll).scroll_home(animate=False)
        self.refresh_bindings()

    def action_copy_candidate(self) -> None:
        """Copy displayed output only, using the existing terminal stdout fallback."""
        if self._active or not self.result or self._delivery_closed:
            return
        text = copy_text(self.result)
        if not text:
            return
        try:
            self.app.copy_to_clipboard(text)
            self.app.notify("Copied candidate", timeout=1.0)
        except Exception:
            print(text)
            self.app.notify("Clipboard unavailable (printed to stdout)", timeout=2.0)

    def action_close(self) -> None:
        """Cancel delivery immediately while backend temp cleanup finishes."""
        self._delivery_closed = True
        self.workers.cancel_node(self)
        self.dismiss()

    def on_unmount(self) -> None:
        """Also prevent delivery after external removal."""
        self._delivery_closed = True
