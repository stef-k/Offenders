"""Application-wide activity presentation over Textual's shared worker lifetime."""
from textual.screen import Screen
from textual.widgets import Static
from textual.worker_manager import WorkerManager

# Explicit human labels avoid exposing Textual's argument-bearing descriptions.
LABEL_PREFIX = "activity:"


class ActivityStatus(Static):
    """Reserve one readable line on every screen, including modal screens."""

    DEFAULT_CSS = """
    ActivityStatus {
        dock: top;
        height: 1;
        background: $surface;
        color: $text;
    }
    """

    def __init__(self):
        super().__init__("", markup=False)

    def on_mount(self):
        """Read current activity even when work began before this screen mounted."""
        self.app.workers.refresh_activity()


class ActivityWorkers(WorkerManager):
    """Observe all decorators/run_worker calls without changing their ownership.

    Textual 8's StateChanged messages do not bubble and may never terminate after
    pre-start cancellation. Its manager completion callback covers both cases.
    The private App._workers installation and _remove_worker hook are deliberately
    confined to this integration; lifecycle behavior is covered by UI tests.
    """

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
        return " · ".join(dict.fromkeys(labels)) + (f" ({len(labels)} active)" if len(labels) > 1 else "")

    def refresh_activity(self):
        """Update mounted presenters without depending on owner message delivery."""
        text = self.activity_text
        for screen in self._app.screen_stack:
            for status in screen.query(ActivityStatus):
                status.update(text)

    def show_on_screen(self, screen: Screen):
        """Install the same app-owned presentation on each newly pushed screen."""
        if screen in self._app.screen_stack and not screen.query(ActivityStatus):
            screen.mount(ActivityStatus())
        self.refresh_activity()
