"""Small DataTable selection checks shared by actions and queued events."""
from textual.widgets import DataTable
from textual.widgets.data_table import RowKey


def current_row_key(table: DataTable) -> RowKey | None:
    """Return a real current row, never Python's negative-index fallback."""
    row = table.cursor_row
    if not 0 <= row < table.row_count or not table.columns:
        return None
    if table.cursor_type == "cell" and not 0 <= table.cursor_column < len(table.columns):
        return None
    return table.coordinate_to_cell_key((row, 0)).row_key


def event_row_key(
    event: DataTable.RowHighlighted | DataTable.RowSelected | DataTable.CellSelected | DataTable.CellHighlighted,
) -> RowKey | None:
    """Accept only an event still identifying the table's current selection."""
    table = event.data_table
    cell_event = isinstance(event, (DataTable.CellSelected, DataTable.CellHighlighted))
    if cell_event:
        key = event.cell_key.row_key if event.cell_key is not None else None
        coordinate = event.coordinate
        if not 0 <= coordinate.column < len(table.columns):
            return None
        row = coordinate.row
    else:
        key, row = event.row_key, event.cursor_row
    if key is None or row != table.cursor_row or key != current_row_key(table):
        return None
    if cell_event:
        if event.cell_key != table.coordinate_to_cell_key(event.coordinate):
            return None
    return key
