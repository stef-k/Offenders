#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import glob
import gzip
import ipaddress
import math
import os
import re
import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Iterable, List, Optional, Tuple

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Container
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Header, RichLog, Static

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
    jail_statuses: List[JailStatus]
    last_10_bans: List[str]

    @property
    def jail_list(self) -> List[str]:
        """Keep the daemon's jail order for the dashboard."""
        return [status.name for status in self.jail_statuses]

    @property
    def bans_per_jail(self) -> List[Tuple[str, int]]:
        """Retain the dashboard's descending ban-count presentation."""
        return sorted(
            [(status.name, status.currently_banned) for status in self.jail_statuses],
            key=lambda item: item[1], reverse=True,
        )


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
                value_line = out[i + 1].strip()
                m = re.search(r"(\d+)", value_line)
                if m:
                    asn = m.group(1)
                break

        for i, line in enumerate(out):
            if "autonomous_system_organization" in line and i + 1 < len(out):
                value_line = out[i + 1].strip()
                value_line = value_line.lstrip().lstrip('"')
                value_line = re.sub(r'".*$', "", value_line)
                if value_line:
                    org = value_line
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


class CommandFailure(str, Enum):
    """Stable failure categories for host-command callers."""

    NOT_FOUND = "command-not-found"
    TIMEOUT = "timeout"
    NONZERO_EXIT = "non-zero-exit"
    EXECUTION = "execution-failure"


@dataclass(frozen=True)
class CommandResult:
    """Separate captured streams from process status and launch diagnostics."""

    returncode: Optional[int]
    stdout: str
    stderr: str
    failure: Optional[CommandFailure] = None
    detail: str = ""


def run_host_command(
    args: List[str], *, timeout: float, sudo: bool = False
) -> CommandResult:
    """Run an argument array with closed stdin and an explicit finite deadline.

    Sudo uses -n to prohibit password prompts. Timeout kills and reaps the
    direct child; its exit code is unavailable, but partial output is retained.
    Missing targets launched through sudo are reported as sudo's non-zero exit.
    """
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be positive and finite")
    if not args or isinstance(args, str):
        raise ValueError("args must be a non-empty argument array")
    command = ["sudo", "-n", *args] if sudo else list(args)
    try:
        process = subprocess.run(
            command, stdin=subprocess.DEVNULL, capture_output=True,
            text=True, encoding="utf-8", errors="replace",
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired as error:
        # TimeoutExpired carries bytes even when subprocess.run uses text mode.
        stdout = (error.stdout or b"").decode("utf-8", errors="replace")
        stderr = (error.stderr or b"").decode("utf-8", errors="replace")
        return CommandResult(None, stdout, stderr, CommandFailure.TIMEOUT, str(error))
    except FileNotFoundError as error:
        return CommandResult(None, "", "", CommandFailure.NOT_FOUND, str(error))
    except (OSError, ValueError) as error:
        return CommandResult(None, "", "", CommandFailure.EXECUTION, str(error))
    failure = CommandFailure.NONZERO_EXIT if process.returncode else None
    return CommandResult(process.returncode, process.stdout, process.stderr, failure)


class Fail2BanCommandError(RuntimeError):
    """Expose the original bounded-runner result without parsing failed stdout."""

    def __init__(self, command: List[str], result: CommandResult):
        self.command = tuple(command)
        self.result = result
        super().__init__(
            f"Fail2Ban {command!r}: {result.failure.value} "
            f"(exit={result.returncode}): {result.stderr or result.detail or result.stdout}"
        )


class Fail2BanParseError(ValueError):
    """Successful command output does not satisfy the required status contract."""


@dataclass(frozen=True)
class JailStatus:
    """Core status plus optional settings; None means unavailable, never zero."""

    name: str
    currently_failed: int
    total_failed: int
    currently_banned: int
    total_banned: int
    banned_ips: Tuple[str, ...]
    bantime: Optional[int] = None
    findtime: Optional[int] = None
    maxretry: Optional[int] = None
    backend: Optional[str] = None
    filter_name: Optional[str] = None
    setting_errors: dict[str, Fail2BanCommandError | Fail2BanParseError] = field(default_factory=dict)


def _run(cmd: List[str]) -> str:
    """Require a successful read-only command, preserving #14 failure details."""
    result = run_host_command(cmd, timeout=8, sudo=True)
    if result.failure is not None:
        raise Fail2BanCommandError(cmd, result)
    return result.stdout


def _status_field(output: str, label: str) -> str:
    """Read exactly one line-local field, including a legitimately empty value."""
    matches = re.findall(
        rf"^[ \t|`-]*{re.escape(label)}:[ \t]*(.*)$", output, re.MULTILINE
    )
    if len(matches) != 1:
        raise Fail2BanParseError(f"Missing or duplicate Fail2Ban field: {label}")
    return matches[0].strip()


def _status_count(output: str, label: str) -> int:
    """Required status counters must be nonnegative decimal integers."""
    value = _status_field(output, label)
    if not re.fullmatch(r"[0-9]+", value):
        raise Fail2BanParseError(f"Invalid Fail2Ban counter: {label}")
    return int(value)


def parse_jail_list(output: str) -> List[str]:
    """Validate the global status, preserving order and valid zero jails."""
    count = _status_count(output, "Number of jail")
    value = _status_field(output, "Jail list")
    jails = [name.strip() for name in value.split(",")] if value else []
    if len(jails) != count or any(not name for name in jails) or len(set(jails)) != count:
        raise Fail2BanParseError("Inconsistent Fail2Ban jail list")
    return jails


def parse_jail_status(output: str, jail: str) -> JailStatus:
    """Parse the shared 1.0.2/1.1.x status fields without a live daemon."""
    if _status_field(output, "Status for the jail") != jail:
        raise Fail2BanParseError(f"Unexpected Fail2Ban jail identity: {jail}")
    counts = [_status_count(output, label) for label in (
        "Currently failed", "Total failed", "Currently banned", "Total banned"
    )]
    try:
        ips = tuple(ipaddress.ip_address(ip).compressed for ip in
                    _status_field(output, "Banned IP list").split())
    except ValueError as error:
        raise Fail2BanParseError(f"Invalid banned IP list for {jail}") from error
    # Counters and IPs are read separately by the daemon; do not require an
    # atomic snapshot or reject legitimate concurrent ban/unban activity.
    return JailStatus(jail, *counts, ips)


def get_jail_list() -> List[str]:
    """Collect required global status or propagate command/parse failure."""
    return parse_jail_list(_run(["fail2ban-client", "status"]))


def get_jail_status(jail: str) -> JailStatus:
    """Collect core status and best-effort 1.0.2 numeric settings, read-only."""
    status = parse_jail_status(_run(["fail2ban-client", "status", jail]), jail)
    settings = {}
    errors = {}
    for name in ("bantime", "findtime", "maxretry"):
        try:
            value = _run(["fail2ban-client", "get", jail, name]).strip()
            if not re.fullmatch(r"-?[0-9]+", value):
                raise Fail2BanParseError(f"Invalid Fail2Ban setting: {jail} {name}")
            settings[name] = int(value)
        except (Fail2BanCommandError, Fail2BanParseError) as error:
            errors[name] = error
    return replace(status, **settings, setting_errors=errors)


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

    jail_statuses = [get_jail_status(jail) for jail in get_jail_list()]

    if not ban_lines:
        return Report(
            generated_at=dt.datetime.now(),
            cutoff_date=cutoff_date,
            total_bans=0,
            ban_lines=[],
            top_offenders=[],
            jail_statuses=jail_statuses,
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

    last10 = ban_lines[-10:] if len(ban_lines) >= 10 else ban_lines[:]

    return Report(
        generated_at=dt.datetime.now(),
        cutoff_date=cutoff_date,
        total_bans=len(ban_lines),
        ban_lines=ban_lines,
        top_offenders=offenders,
        jail_statuses=jail_statuses,
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


class CommandOutputModal(ModalScreen[None]):
    BINDINGS = [
        ("escape", "dismiss", "Close"),
        ("q", "dismiss", "Close"),
        ("c", "copy_output", "Copy output"),
    ]

    def __init__(self, title: str, cmd: List[str]) -> None:
        super().__init__()
        self._title = title
        self._cmd = cmd
        self._output_text = ""

    def compose(self) -> ComposeResult:
        yield Static(self._title, id="cmd-title")
        yield RichLog(id="cmd-out", wrap=True, highlight=True)

    def on_mount(self) -> None:
        out = self.query_one("#cmd-out", RichLog)
        out.write(f"$ {' '.join(self._cmd)}")
        out.write("")
        self._run()

    @work(thread=True)
    def _run(self) -> None:
        out_text = ""
        try:
            p = subprocess.run(
                self._cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=8,
            )
            out_text = (p.stdout or "") + (p.stderr or "")
            if not out_text.strip():
                out_text = "(no output)"
        except FileNotFoundError:
            out_text = (
                "Command not found. Install the required package (whois / dnsutils)."
            )
        except subprocess.TimeoutExpired:
            out_text = "Command timed out."
        except Exception as ex:
            out_text = f"Command failed: {ex}"

        # Cap output so the UI stays responsive
        if len(out_text) > 200_000:
            out_text = out_text[:200_000] + "\n\n(output truncated)\n"

        self._output_text = out_text
        self.app.call_from_thread(self._render_output, out_text)

    def _render_output(self, text: str) -> None:
        out = self.query_one("#cmd-out", RichLog)
        for line in text.splitlines():
            out.write(line)

    def action_copy_output(self) -> None:
        if not self._output_text:
            return
        try:
            self.app.copy_to_clipboard(self._output_text)  # type: ignore[attr-defined]
            self.app.notify("Copied output", timeout=1.0)  # type: ignore[attr-defined]
        except Exception:
            print(self._output_text)
            self.app.notify("Clipboard unavailable (printed to stdout)", timeout=2.0)  # type: ignore[attr-defined]


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
        ("w", "whois", "Whois"),
        ("d", "rdns", "RDNS"),
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

    def _selected_ip(self) -> Optional[str]:
        table = self.focused
        if not isinstance(table, DataTable):
            return None

        idx = self._cursor_indexes(table)
        if idx is None:
            return None
        row_index, _ = idx

        ip_col = None
        if table.id == "offenders":
            ip_col = 1  # Bans, IP, Country, ASN, Org
        elif table.id == "last-bans":
            ip_col = 3  # Date, Time, Jail, IP
        else:
            return None

        val = self._cell_value_at(table, row_index, ip_col)
        if val is None:
            return None

        ip = str(val).strip()
        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            return None

    def action_whois(self) -> None:
        ip = self._selected_ip()
        if not ip:
            self.notify(
                "Select an IP in the Top banned IPs or Last bans tables", timeout=2.0
            )
            return

        if shutil.which("whois") is None:
            self.notify("Missing 'whois' command (install package: whois)", timeout=3.0)
            return

        self.push_screen(CommandOutputModal(f"WHOIS {ip}", ["whois", ip]))

    def action_rdns(self) -> None:
        ip = self._selected_ip()
        if not ip:
            self.notify(
                "Select an IP in the Top banned IPs or Last bans tables", timeout=2.0
            )
            return

        if shutil.which("dig") is not None:
            cmd = ["dig", "+short", "-x", ip]
            title = f"RDNS (dig -x) {ip}"
        else:
            # Fallback that works on most Linux systems without dnsutils
            cmd = ["getent", "hosts", ip]
            title = f"RDNS (getent hosts) {ip}"

        self.push_screen(CommandOutputModal(title, cmd))

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


def main() -> None:
    """Launch the dashboard from the installed command or source checkout."""
    OffendersApp().run()


if __name__ == "__main__":
    main()
