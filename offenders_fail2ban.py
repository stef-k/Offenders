"""Bound read-only Fail2Ban commands and parse structured daemon status."""
from __future__ import annotations

import ipaddress
import math
import re
import subprocess
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import List, Optional, Tuple

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
    """Require a successful read-only command, preserving bounded-runner failure details."""
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


# Bound source evidence independently of the subprocess timeout.
SOURCE_TEXT_LIMIT = 65536


@dataclass(frozen=True)
class JailSources:
    """Independent optional runtime source facts with original failure details."""

    name: str
    logpaths: tuple[str, ...] | None
    journalmatch: str | None
    journal_units: tuple[str, ...]
    errors: dict[str, Fail2BanCommandError | Fail2BanParseError] = field(default_factory=dict)


def journal_units(expression: str) -> tuple[str, ...]:
    """Extract whole literal unit tokens, never prefixes or interpolation."""
    return tuple(sorted(set(token.split("=", 1)[1] for token in expression.split()
                            if re.fullmatch(r"_SYSTEMD_UNIT=[A-Za-z0-9_.@:\\-]+", token))))


def parse_logpaths(output: str) -> tuple[str, ...]:
    """Accept the 1.0.2 beautifier's empty sentinel or concrete tree entries."""
    if len(output) > SOURCE_TEXT_LIMIT:
        raise Fail2BanParseError("Runtime logpath output exceeds source bound")
    lines = output.strip().splitlines()
    if lines == ["No file is currently monitored"]:
        return ()
    if len(lines) < 2 or lines[0] != "Current monitored log file(s):":
        raise Fail2BanParseError("Invalid runtime logpath header or missing entries")
    paths = []
    for line in lines[1:]:
        match = re.fullmatch(r"(?:\|- |`- |\\- )(/[^\r\n]+)", line)
        if not match:
            raise Fail2BanParseError("Invalid runtime logpath entry")
        paths.append(match[1])
    return tuple(sorted(set(paths)))


def parse_journalmatch(output: str) -> str:
    """Preserve a bounded raw expression, distinguishing empty from malformed."""
    if len(output) > SOURCE_TEXT_LIMIT:
        raise Fail2BanParseError("Runtime journalmatch output exceeds source bound")
    value = output.strip()
    if value == "No journal match filter set":
        return ""
    header = "Current match filter:\n"
    if not value.startswith(header) or not value[len(header):].strip():
        raise Fail2BanParseError("Invalid runtime journalmatch output")
    expression = value[len(header):].strip()
    if any(token != "+" and not re.fullmatch(r"[A-Z_][A-Z_0-9]*=\S+", token)
           for token in expression.split()):
        raise Fail2BanParseError("Invalid runtime journalmatch expression")
    if not any("=" in token for token in expression.split()):
        raise Fail2BanParseError("Missing runtime journalmatch terms")
    return expression


def get_jail_sources(jail: str) -> JailSources:
    """Query only stable source commands through the existing eight-second seam."""
    values = {"logpath": None, "journalmatch": None}
    errors = {}
    for name, parser in (("logpath", parse_logpaths), ("journalmatch", parse_journalmatch)):
        try:
            values[name] = parser(_run(["fail2ban-client", "get", jail, name]))
        except (Fail2BanCommandError, Fail2BanParseError) as error:
            errors[name] = error
    return JailSources(jail, values["logpath"], values["journalmatch"],
                       journal_units(values["journalmatch"] or ""), errors)
