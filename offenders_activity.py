"""Application-wide activity presentation over Textual's shared worker lifetime."""
from time import monotonic

from textual.screen import Screen
from textual.widget import Widget
from textual.widgets import Footer, Static
from textual.worker_manager import WorkerManager

# Explicit human labels avoid exposing Textual's argument-bearing descriptions.
LABEL_PREFIX = "activity:"


class ActivityStatus(Static):
    """Literal, ellipsized activity label within the universal footer."""

    DEFAULT_CSS = """
    ActivityStatus {
        width: auto;
        max-width: 45%;
        height: 1;
        text-wrap: nowrap;
        text-overflow: ellipsis;
        text-align: right;
    }
    """

    def __init__(self):
        super().__init__("", markup=False)

    def on_mount(self):
        """Read shared presentation even when work finished before mounting."""
        self.app.workers.refresh_activity()


class OffendersFooter(Widget):
    """Keep native contextual bindings and bounded activity on one bottom row."""

    DEFAULT_CSS = """
    OffendersFooter {
        dock: bottom;
        layout: horizontal;
        height: 1;
        background: $footer-background;
        color: $footer-foreground;
    }
    OffendersFooter > Footer {
        dock: none;
        width: 1fr;
        min-width: 0;
    }
    """

    def compose(self):
        """Delegate binding visibility, scrolling, and clicks to Textual."""
        yield Footer()
        yield ActivityStatus()


class ActivityWorkers(WorkerManager):
    """Observe all decorators/run_worker calls without changing their ownership.

    Textual 8's StateChanged messages do not bubble and may never terminate after
    pre-start cancellation. Its manager completion callback covers both cases.
    The private App._workers installation and _remove_worker hook are deliberately
    confined to this integration; lifecycle behavior is covered by UI tests.
    """

    MINIMUM_VISIBLE = 0.5
    """Minimum continuous presentation time; never extends a worker lifetime."""

    def __init__(self, app):
        super().__init__(app)
        self._presented_text = ""
        self._visible_until = 0.0
        self._clear_timer = None

    def add_worker(self, worker, start=True, exclusive=True):
        """Publish accepted work synchronously before its scheduled task can run."""
        super().add_worker(worker, start=start, exclusive=exclusive)
        self.refresh_activity()

    def start_all(self):
        """Include explicitly deferred workers once Textual starts them."""
        super().start_all()
        self.refresh_activity()

    def _remove_worker(self, worker):
        """Release exactly one activity on success, error, or any cancellation."""
        super()._remove_worker(worker)
        self.refresh_activity()

    def label(self, worker, text):
        """Optionally specialize one operation without acquiring another token."""
        worker.name = LABEL_PREFIX + text
        self.refresh_activity()

    @property
    def activity_text(self):
        """Derive overlapping activity from authoritative worker identities."""
        labels = [worker.name.removeprefix(LABEL_PREFIX)
                  if worker.name.startswith(LABEL_PREFIX) else "Working…"
                  for worker in self if worker.is_running and not worker.is_cancelled]
        return ("⏳ " + labels[0] + (f" (+{len(labels) - 1})" if len(labels) > 1 else "")) if labels else ""

    def refresh_activity(self):
        """Update mounted presenters without depending on owner message delivery."""
        text = self.activity_text
        if self._clear_timer is not None:
            self._clear_timer.stop()
            self._clear_timer = None
        if text:
            if not self._presented_text:
                self._visible_until = monotonic() + self.MINIMUM_VISIBLE
            self._presented_text = text
        elif self._presented_text:
            remaining = self._visible_until - monotonic()
            if remaining > 0:
                self._clear_timer = self._app.set_timer(remaining, self.refresh_activity)
            else:
                self._presented_text = ""
        for screen in self._app.screen_stack:
            for status in screen.query(ActivityStatus):
                status.update(self._presented_text)

    def show_on_screen(self, screen: Screen):
        """Install the same app-owned presentation on each newly pushed screen."""
        if screen in self._app.screen_stack and not screen.query(OffendersFooter):
            screen.mount(OffendersFooter())
        self.refresh_activity()
