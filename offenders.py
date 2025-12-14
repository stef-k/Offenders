#!usr/bin/python
from __future__ import annotations

import datetime as dt
import glob
import gzip
import ipaddress
import os
import re
import subprocess
from collections import Counter
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Container
from textual.widgets import DataTable, Footer, Header, Static

# =========================
# Config
# =========================

LOG_CURRENT = "/var/log/fail2ban.log"
LOG_ROTATED = "/var/log/fail2ban.log.1"
LOG_GZ_GLOB = "/var/log/fail2ban.log.*.gz"

GEO_COUNTRY_DB = "/usr/share/GeoIP/dbip-country-lite.mmdb"
GEO_ASN_DB = "/usr/share/GeoIP/dbip-asn-lite.mmdb"

TOP_COUNT = 20
LOOKBACK_DAYS = 7  # 0 => all available
IGNORE_PRIVATE = True  # skip RFC1918/private IPs (and IPv6 equivalents)

# Match the token after "Ban" (IPv4 or IPv6-ish), then validate with ipaddress.ip_address()
BAN_IP_RE = re.compile(r"\bBan\s+([0-9A-Fa-f:.]+)\b")

# Tolerant helpers for the "Last bans" table
BAN_LINE_TIME_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})(?:,\d+)?\s+"
)
BRACKET_RE = re.compile(r"\[([^\]]+)\]")

# Do not set lower than 30 seconds as geoip/asn lookups may be slow
CHECK_INTERVAL_SECONDS = 30

# =========================
# Models
# =========================


@dataclass(frozen=True)
class Offender:
    ip: str
    count: int
    country: str
    asn: str
    asn_org: str


@dataclass(frozen=True)
class Report:
    generated_at: dt.datetime
    cutoff_date: Optional[dt.date]  # None if LOOKBACK_DAYS == 0
    total_bans: int
    ban_lines: List[str]  # filtered Ban lines (selected period)
    top_offenders: List[Offender]
    jail_list: List[str]
    bans_per_jail: List[Tuple[str, int]]  # (jail, currently banned)
    last_10_bans: List[str]


# =========================
# Log reading
# =========================


def _gz_rot_num(path: str) -> int:
    m = re.search(r"\.(\d+)\.gz$", path)
    return int(m.group(1)) if m else 0


def _log_files() -> List[str]:
    files: List[str] = []

    gz_files = glob.glob(LOG_GZ_GLOB)
    # fail2ban.log.2.gz is newer than .3.gz, so sort descending so oldest comes first
    gz_files = sorted(gz_files, key=_gz_rot_num, reverse=True)
    files.extend(gz_files)

    if os.path.isfile(LOG_ROTATED):
        files.append(LOG_ROTATED)

    if os.path.isfile(LOG_CURRENT):
        files.append(LOG_CURRENT)

    return files


def _iter_lines(path: str) -> Iterable[str]:
    if path.endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            yield from f
    else:
        with open(path, "rt", encoding="utf-8", errors="replace") as f:
            yield from f


def iter_unified_log_stream() -> Iterable[str]:
    for path in _log_files():
        try:
            yield from _iter_lines(path)
        except FileNotFoundError:
            continue


# =========================
# Filtering Ban lines
# =========================


def parse_log_date(line: str) -> Optional[dt.date]:
    parts = line.split()
    if not parts:
        return None
    try:
        return dt.date.fromisoformat(parts[0])
    except ValueError:
        return None


def is_real_ban_line(line: str) -> bool:
    m = BAN_IP_RE.search(line)
    if not m:
        return False
    token = m.group(1)
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


def collect_ban_lines(lookback_days: int) -> Tuple[List[str], Optional[dt.date]]:
    ban_lines: List[str] = []

    cutoff_date: Optional[dt.date] = None
    if lookback_days and lookback_days > 0:
        cutoff_date = dt.datetime.now().date() - dt.timedelta(days=lookback_days)

    for line in iter_unified_log_stream():
        if not is_real_ban_line(line):
            continue

        if cutoff_date is not None:
            d = parse_log_date(line)
            if d is None or d < cutoff_date:
                continue

        ban_lines.append(line.rstrip("\n"))

    return ban_lines, cutoff_date


def extract_ips(ban_lines: Iterable[str]) -> List[str]:
    ips: List[str] = []
    for line in ban_lines:
        m = BAN_IP_RE.search(line)
        if not m:
            continue
        token = m.group(1)
        try:
            ips.append(ipaddress.ip_address(token).compressed)
        except ValueError:
            continue
    return ips


def filter_private_ips(ips: Iterable[str]) -> List[str]:
    out: List[str] = []
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue

        if addr.is_private or addr.is_loopback or addr.is_link_local:
            continue

        out.append(ip)
    return out


# =========================
# Geo/ASN lookups
# =========================


def _geoip2_lookup(ip: str) -> Optional[Tuple[str, str, str]]:
    try:
        import geoip2.database  # type: ignore
    except Exception:
        return None

    country = "Unknown"
    asn = "No ASN"
    asn_org = "No ASN org"

    try:
        if os.path.isfile(GEO_COUNTRY_DB):
            with geoip2.database.Reader(GEO_COUNTRY_DB) as r:
                resp = r.country(ip)
                if resp and resp.country and resp.country.name:
                    country = resp.country.name
    except Exception:
        pass

    try:
        if os.path.isfile(GEO_ASN_DB):
            with geoip2.database.Reader(GEO_ASN_DB) as r:
                resp = r.asn(ip)
                if resp and resp.autonomous_system_number:
                    asn = str(resp.autonomous_system_number)
                if resp and resp.autonomous_system_organization:
                    asn_org = resp.autonomous_system_organization
    except Exception:
        pass

    return country, asn, asn_org


def _mmdblookup_country(ip: str) -> str:
    if not os.path.isfile(GEO_COUNTRY_DB):
        return "Unknown"

    try:
        p = subprocess.run(
            ["mmdblookup", "--file", GEO_COUNTRY_DB, "--ip", ip],
            capture_output=True,
            text=True,
            check=False,
        )
        txt = p.stdout.replace("\n", " ")
        m = re.search(r'"country".*?"en"\s*:\s*"([^"]+)"', txt)
        return m.group(1) if m else "Unknown"
    except Exception:
        return "Unknown"


def _mmdblookup_asn(ip: str) -> Tuple[str, str]:
    if not os.path.isfile(GEO_ASN_DB):
        return "No ASN", "No ASN org"

    try:
        p = subprocess.run(
            ["mmdblookup", "--file", GEO_ASN_DB, "--ip", ip],
            capture_output=True,
            text=True,
            check=False,
        )
        out = p.stdout.splitlines()

        asn = "No ASN"
        org = "No ASN org"

        for i, line in enumerate(out):
            if "autonomous_system_number" in line and i + 1 < len(out):
                cand = out[i + 1].strip().strip('"').strip(",")
                if cand.isdigit():
                    asn = cand
                break

        for i, line in enumerate(out):
            if "autonomous_system_organization" in line and i + 1 < len(out):
                cand = out[i + 1].strip()
                cand = cand.lstrip().lstrip('"')
                cand = re.sub(r'".*$', "", cand)
                if cand:
                    org = cand
                break

        return asn, org
    except Exception:
        return "No ASN", "No ASN org"


def geo_lookup(ip: str) -> Tuple[str, str, str]:
    got = _geoip2_lookup(ip)
    if got is not None:
        return got

    country = _mmdblookup_country(ip)
    asn, org = _mmdblookup_asn(ip)
    return country or "Unknown", asn or "No ASN", org or "No ASN org"


# =========================
# fail2ban-client helpers
# =========================


def _run(cmd: List[str]) -> str:
    p = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return (p.stdout or "") + (p.stderr or "")


def get_jail_list() -> List[str]:
    out = _run(["sudo", "fail2ban-client", "status"])
    m = re.search(r"Jail list:\s*(.*)", out)
    if not m:
        return []
    return [j.strip() for j in m.group(1).split(",") if j.strip()]


def get_currently_banned_for_jail(jail: str) -> int:
    out = _run(["sudo", "fail2ban-client", "status", jail])
    m = re.search(r"Currently banned:\s*(\d+)", out)
    return int(m.group(1)) if m else 0


# =========================
# Main report builder
# =========================


def build_report(
    top_count: int = TOP_COUNT,
    lookback_days: int = LOOKBACK_DAYS,
    ignore_private: bool = IGNORE_PRIVATE,
) -> Report:
    if not (os.path.isfile(LOG_CURRENT) or os.path.isfile(LOG_ROTATED)):
        raise FileNotFoundError(
            f"No Fail2Ban logs found at {LOG_CURRENT} or {LOG_ROTATED}"
        )

    ban_lines, cutoff_date = collect_ban_lines(lookback_days)

    if not ban_lines:
        jails = get_jail_list()
        bans_per = [(j, get_currently_banned_for_jail(j)) for j in jails]
        bans_per.sort(key=lambda x: x[1], reverse=True)
        return Report(
            generated_at=dt.datetime.now(),
            cutoff_date=cutoff_date,
            total_bans=0,
            ban_lines=[],
            top_offenders=[],
            jail_list=jails,
            bans_per_jail=bans_per,
            last_10_bans=[],
        )

    ips = extract_ips(ban_lines)
    if ignore_private:
        ips = filter_private_ips(ips)

    counts = Counter(ips)
    top = counts.most_common(top_count)

    offenders: List[Offender] = []
    for ip, c in top:
        country, asn, asn_org = geo_lookup(ip)
        offenders.append(
            Offender(
                ip=ip,
                count=c,
                country=country or "Unknown",
                asn=asn or "No ASN",
                asn_org=asn_org or "No ASN org",
            )
        )

    jails = get_jail_list()
    bans_per = [(j, get_currently_banned_for_jail(j)) for j in jails]
    bans_per.sort(key=lambda x: x[1], reverse=True)

    last10 = ban_lines[-10:] if len(ban_lines) >= 10 else ban_lines[:]

    return Report(
        generated_at=dt.datetime.now(),
        cutoff_date=cutoff_date,
        total_bans=len(ban_lines),
        ban_lines=ban_lines,
        top_offenders=offenders,
        jail_list=jails,
        bans_per_jail=bans_per,
        last_10_bans=last10,
    )


# =========================
# Textual UI
# =========================


def _format_period(cutoff: Optional[dt.date]) -> str:
    today = dt.date.today()
    if cutoff:
        return f"{cutoff.isoformat()} → {today.isoformat()} (last {LOOKBACK_DAYS} days)"
    return "all available logs"


def _parse_ban_line_for_table(line: str) -> Tuple[str, str, str, str]:
    """
    Returns: (date, time, jail, ip)
    Always returns a row (never filters out lines here).
    """
    date = ""
    time = ""
    jail = ""
    ip = ""

    mt = BAN_LINE_TIME_RE.search(line)
    if mt:
        date = mt.group("date")
        time = mt.group("time")

    brackets = BRACKET_RE.findall(line)
    if brackets:
        for token in brackets:
            token = token.strip()
            if not token:
                continue
            if token.isdigit():
                continue  # skip PID like [996]

            # skip logger-ish tokens; keep actual jails
            low = token.lower()
            if low.startswith("fail2ban."):
                continue

            jail = token
            break

    mi = BAN_IP_RE.search(line)
    if mi:
        token = mi.group(1)
        try:
            ip = ipaddress.ip_address(token).compressed
        except ValueError:
            ip = ""

    return (date, time, jail, ip)


class SummaryBar(Static):
    def update_from_report(self, r: Report) -> None:
        now = r.generated_at
        period = _format_period(r.cutoff_date)
        self.update(
            f"🕒 {now:%Y-%m-%d %H:%M:%S} | 🔢 bans={r.total_bans} | period={period}"
            + f" | reports updating every {CHECK_INTERVAL_SECONDS} seconds"
        )


class OffendersApp(App):
    CSS = """
    Screen { layout: vertical; }

    #body { height: 1fr; padding: 1; }
    #summary { padding: 0 0 1 0; }

    .section-title { padding: 1 0 0 0; }

    /* Keep everything fitting so the bottom table isn't clipped */
    #offenders { height: 10; }
    #jails-line { height: auto; }
    #bans-per-jail { height: 7; }

    /* Bottom table uses the remaining space (and will scroll internally) */
    #last-bans { height: 1fr; min-height: 6; }
    """

    # Consolidated copy action: copies row in row-cursor mode, copies cell in cell-cursor mode
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("c", "copy_selection", "Copy"),
        ("x", "copy_selection", "Copy"),
        ("t", "toggle_cursor", "Row/Cell"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()

        with Container(id="body"):
            yield SummaryBar(id="summary")

            yield Static("🔥 Top banned IPs", classes="section-title")
            yield DataTable(id="offenders")

            yield Static("🧱 Current active jails", classes="section-title")
            yield Static("", id="jails-line")

            yield Static("📊 Active bans per jail", classes="section-title")
            yield DataTable(id="bans-per-jail")

            yield Static("🕒 Last bans from selected logs", classes="section-title")
            yield DataTable(id="last-bans")

        yield Footer()

    def on_mount(self) -> None:
        self.title = "Fail2Ban Top Offenders"
        self.sub_title = "Updated at: —"

        offenders = self.query_one("#offenders", DataTable)
        offenders.add_columns("Bans", "IP", "Country", "ASN", "Org")
        offenders.cursor_type = "row"

        bans_per_jail = self.query_one("#bans-per-jail", DataTable)
        bans_per_jail.add_columns("Jail", "Currently banned")
        bans_per_jail.cursor_type = "row"

        last_bans = self.query_one("#last-bans", DataTable)
        # Removed raw line column; keep it clean
        last_bans.add_columns("Date", "Time", "Jail", "IP")
        last_bans.cursor_type = "row"

        # Ensure scrollbars are enabled for the widget
        last_bans.show_vertical_scrollbar = True
        last_bans.show_horizontal_scrollbar = True

        self.refresh_report()
        self.set_interval(CHECK_INTERVAL_SECONDS, self.refresh_report)

    def action_refresh(self) -> None:
        self.refresh_report()

    @work(thread=True)
    def refresh_report(self) -> None:
        try:
            r = build_report()
            self.call_from_thread(self._apply_report, r, None)
        except Exception as ex:
            self.call_from_thread(self._apply_report, None, str(ex))

    def _copy_text(self, text: str) -> None:
        # Clipboard support depends on terminal/OS; fallback prints.
        try:
            self.copy_to_clipboard(text)
            self.notify("Copied", timeout=1.0)
        except Exception:
            print(text)
            self.notify("Clipboard unavailable (printed to stdout)", timeout=2.0)

    # ---- Copy helpers (robust across Textual versions) ----

    def _cursor_indexes(self, table: DataTable) -> Optional[Tuple[int, int]]:
        """
        Returns (row_index, col_index) in display order, if possible.
        Falls back to mapping row/col keys to indices.
        """
        coord = getattr(table, "cursor_coordinate", None)
        if coord is not None:
            try:
                return (coord.row, coord.column)
            except Exception:
                pass

        row_key = getattr(table, "cursor_row", None)
        col_key = getattr(table, "cursor_column", None)
        if row_key is None:
            return None

        try:
            row_keys = getattr(table, "row_keys", None)
            if row_keys is not None:
                row_index = list(row_keys).index(row_key)
            else:
                return None
        except Exception:
            return None

        if col_key is None:
            return (row_index, -1)

        try:
            # table.columns contains Column objects; compare by .key
            col_index = -1
            for i, col in enumerate(table.columns):
                if getattr(col, "key", None) == col_key:
                    col_index = i
                    break
            return (row_index, col_index)
        except Exception:
            return (row_index, -1)

    def _row_values_at(self, table: DataTable, row_index: int) -> Tuple[object, ...]:
        # Prefer direct index API if available
        if hasattr(table, "get_row_at"):
            return table.get_row_at(row_index)  # type: ignore[attr-defined]

        row_keys = getattr(table, "row_keys", None)
        if row_keys is None:
            return tuple()

        row_key = list(row_keys)[row_index]
        return table.get_row(row_key)

    def _cell_value_at(
        self, table: DataTable, row_index: int, col_index: int
    ) -> Optional[object]:
        if row_index < 0 or col_index < 0:
            return None

        # Prefer direct index API if available
        if hasattr(table, "get_cell_at"):
            try:
                return table.get_cell_at(row_index, col_index)  # type: ignore[attr-defined]
            except Exception:
                pass

        # Fall back to key-based cell access if possible
        try:
            row_keys = getattr(table, "row_keys", None)
            if row_keys is not None and col_index < len(table.columns):
                row_key = list(row_keys)[row_index]
                col_key = getattr(table.columns[col_index], "key", None)
                if col_key is not None:
                    return table.get_cell(row_key, col_key)
        except Exception:
            pass

        # Last resort: row tuple + column index
        try:
            row = self._row_values_at(table, row_index)
            if 0 <= col_index < len(row):
                return row[col_index]
        except Exception:
            pass

        return None

    # ---- Consolidated copy action ----

    def action_copy_selection(self) -> None:
        table = self.focused
        if not isinstance(table, DataTable):
            return

        idx = self._cursor_indexes(table)
        if idx is None:
            return

        row_index, col_index = idx

        # In row mode, copy entire row (even if we also have a column)
        if table.cursor_type == "row":
            row = self._row_values_at(table, row_index)
            if not row:
                return
            self._copy_text("\t".join(str(v) for v in row))
            return

        # In cell mode, copy cell value
        val = self._cell_value_at(table, row_index, col_index)
        if val is None:
            return
        self._copy_text(str(val))

    # Backwards-compatible action names (in case you kept old keybindings elsewhere)
    def action_copy_row(self) -> None:
        table = self.focused
        if isinstance(table, DataTable):
            old = table.cursor_type
            table.cursor_type = "row"
            try:
                self.action_copy_selection()
            finally:
                table.cursor_type = old

    def action_copy_cell(self) -> None:
        table = self.focused
        if isinstance(table, DataTable):
            old = table.cursor_type
            table.cursor_type = "cell"
            try:
                self.action_copy_selection()
            finally:
                table.cursor_type = old

    def action_toggle_cursor(self) -> None:
        table = self.focused
        if not isinstance(table, DataTable):
            return

        if table.cursor_type == "row":
            table.cursor_type = "cell"
        else:
            table.cursor_type = "row"

    def _apply_report(self, r: Optional[Report], error: Optional[str]) -> None:
        summary = self.query_one("#summary", SummaryBar)
        offenders = self.query_one("#offenders", DataTable)
        jails_line = self.query_one("#jails-line", Static)
        bans_per_jail = self.query_one("#bans-per-jail", DataTable)
        last_bans = self.query_one("#last-bans", DataTable)

        offenders.clear()
        bans_per_jail.clear()
        last_bans.clear()

        if error:
            now = dt.datetime.now()
            summary.update(f"❌ {now:%Y-%m-%d %H:%M:%S} | {error}")
            jails_line.update("")
            offenders.add_row("—", "—", "—", "—", "—")
            bans_per_jail.add_row("—", "—")
            last_bans.add_row("", "", "", "")
            return

        assert r is not None

        summary.update_from_report(r)
        self.sub_title = f"Updated at: {r.generated_at:%Y-%m-%d %H:%M:%S}"

        # Top offenders table
        if r.top_offenders:
            for o in r.top_offenders:
                asn_display = f"AS{o.asn}" if o.asn.isdigit() else o.asn
                offenders.add_row(str(o.count), o.ip, o.country, asn_display, o.asn_org)
        else:
            offenders.add_row("0", "(none)", "", "", "")

        # Active jails line
        jails_line.update(", ".join(r.jail_list) if r.jail_list else "(no jails found)")

        # Bans per jail table
        if r.bans_per_jail:
            for jail, c in r.bans_per_jail:
                bans_per_jail.add_row(jail, str(c))
        else:
            bans_per_jail.add_row("(none)", "0")

        # Last bans table: always show all last 10 lines (clean columns only)
        if r.last_10_bans:
            for line in r.last_10_bans:
                d, t, jail, ip = _parse_ban_line_for_table(line)
                last_bans.add_row(d, t, jail, ip)
        else:
            last_bans.add_row("", "", "", "(no ban lines in selected period)")


if __name__ == "__main__":
    OffendersApp().run()
