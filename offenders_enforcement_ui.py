"""Dedicated manual Enforcement presentation and single-flight worker lifecycle."""
from collections import Counter
import json

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.worker import Worker, get_current_worker
from textual.widgets import DataTable, Static

from offenders_activity import OffendersFooter
from offenders_enforcement import EnforcementResult, EnforcementRow, check_enforcement
from offenders_selection import current_row_key, event_row_key


def row_detail(row: EnforcementRow) -> str:
    """Render literal bounded facts; backend evidence is retained without raw output."""
    lines = [f'Result: {row.outcome}', f'Reason: {row.reason}',
             f'Jail: {row.jail}', f'IP: {row.ip or "not applicable"}',
             f'Action: {row.action or "not applicable"}', f'Backend: {row.backend or "not applicable"}']
    if row.backend_reason:
        lines.append(f'Backend evidence: {row.backend_reason}')
    for label, names in (('Unclassified actions', row.unclassified_actions),
                         ('Metadata unavailable / ambiguous actions', row.unavailable_actions)):
        if names:
            lines.append(f'{label} ({len(names)}): ' + ', '.join(names))
    if row.backend == 'ufw':
        lines.extend((f'UFW managed rule: {row.managed_rule}', f'UFW live rule: {row.live_rule}',
                      f'Connection termination: {row.connection_termination}'))
    lines.append('Direct rule/object observation is not packet or reachability proof.')
    return '\n'.join(lines)


class EnforcementScreen(Screen):
    """One manual check per opening/recheck; closure rejects cancelled late delivery."""

    BINDINGS = [('r', 'recheck', 'Recheck'), ('escape', 'close', 'Close'), ('q', 'close', 'Close')]
    DEFAULT_CSS = """
    EnforcementScreen { layout: vertical; }
    #enforcement-summary { height: auto; max-height: 7; }
    #enforcement-rows { height: 1fr; min-height: 4; }
    #enforcement-scroll { height: 1fr; }
    """

    def __init__(self):
        """Result ownership and row keys are local to this screen and check generation."""
        super().__init__()
        self.result: EnforcementResult | None = None
        self.rows: dict[str, EnforcementRow] = {}
        self._worker: Worker | None = None
        self._generation = 0
        self._delivery_closed = False

    def compose(self) -> ComposeResult:
        """Keep selected detail independently scrollable with the shared activity footer."""
        yield Static('Enforcement\nChecking…', id='enforcement-summary', markup=False)
        yield DataTable(id='enforcement-rows', cursor_type='row')
        with VerticalScroll(id='enforcement-scroll'):
            yield Static('', id='enforcement-detail', markup=False)
        yield OffendersFooter()

    def on_mount(self) -> None:
        """Opening explicitly starts one check; there is no enforcement timer."""
        table = self.query_one(DataTable)
        table.add_columns('Result', 'Jail', 'Action', 'Backend', 'IP', 'Evidence')
        table.focus()
        self.action_recheck()

    def action_recheck(self) -> None:
        """Ignore overlapping requests and clear old evidence before new acquisition."""
        if self._delivery_closed or (self._worker is not None and not self._worker.is_finished):
            return
        self._generation += 1
        self.result = None
        self.rows.clear()
        self.query_one(DataTable).clear()
        self.query_one('#enforcement-detail', Static).update('')
        self.query_one('#enforcement-summary', Static).update('Enforcement\nChecking…')
        self._worker = self._check()

    @work(thread=True, name='activity:Checking enforcement…')
    def _check(self) -> None:
        """Run acquisition off-loop, publishing no arbitrary exception diagnostics."""
        worker, app = get_current_worker(), self.app
        try:
            result = check_enforcement()
        except Exception:
            result = EnforcementResult(reason='check-unavailable')
        if not worker.is_cancelled:
            app.call_from_thread(self._complete, result, worker)

    def _complete(self, result: EnforcementResult, worker: Worker) -> None:
        """Only the current, mounted, open screen may accept this worker's result."""
        if self._delivery_closed or not self.is_mounted or worker is not self._worker or worker.is_cancelled:
            return
        self.result = result
        summary = 'Enforcement\n'
        if result.reason:
            summary += f'Check unavailable: {result.reason}'
        elif result.rows:
            summary += '; '.join(f'{name}: {count}' for name, count in Counter(r.outcome for r in result.rows).items())
        else:
            summary += 'No active jails.'
        if result.collected_at is not None:
            summary += '\nCheck completed: ' + result.collected_at.isoformat()
        summary += '\nDirect rule/object observation is not packet or reachability proof.'
        self.query_one('#enforcement-summary', Static).update(Text(summary))
        table = self.query_one(DataTable)
        for row in result.rows:
            key = json.dumps((self._generation, *row.identity), separators=(',', ':'))
            self.rows[key] = row
            table.add_row(*(Text(cell or '—') for cell in
                            (row.outcome, row.jail, row.action, row.backend, row.ip, row.reason)), key=key)
        key = current_row_key(table)
        if key is not None:
            self._show_detail(key.value)

    @on(DataTable.RowHighlighted, '#enforcement-rows')
    @on(DataTable.RowSelected, '#enforcement-rows')
    def highlight_row(self, event: DataTable.RowHighlighted | DataTable.RowSelected) -> None:
        """Queued empty/stale events cannot resolve into another check's evidence."""
        key = event_row_key(event)
        if key is not None and not self._delivery_closed:
            self._show_detail(key.value)

    def _show_detail(self, key: str) -> None:
        """Look up immutable row identity rather than interpreting display cells."""
        row = self.rows.get(key)
        if row is not None:
            self.query_one('#enforcement-detail', Static).update(Text(row_detail(row)))
            self.query_one('#enforcement-scroll', VerticalScroll).scroll_home(animate=False)

    def action_close(self) -> None:
        """Close delivery before cancellation/removal; bounded reads may still finish."""
        self._delivery_closed = True
        self.workers.cancel_node(self)
        self.dismiss()

    def on_unmount(self) -> None:
        """Also reject delivery after removal outside the local close action."""
        self._delivery_closed = True
        self.workers.cancel_node(self)
