"""Offline contracts for normalized history and exact period report selection."""

import datetime as dt
import gzip
from pathlib import Path
import tempfile
import unittest
from unittest.mock import call, patch

import offenders_events as events
import offenders_report as reports


class ParsingTests(unittest.TestCase):
    """Exercise complete event parsing without UI or enrichment tools."""

    def test_timestamp_ip_and_jail_normalization(self):
        """Preserve local microseconds and skip PID/logger bracket tokens."""
        for fraction, microseconds in [("", 0), (",1", 100000), (",123456", 123456), (".789", 789000)]:
            with self.subTest(fraction=fraction):
                line = f"2024-02-29 12:34:56{fraction} [fail2ban.actions] [996]: NOTICE [nginx-http-auth] Ban 2606:4700:0:0:0:0:0:ABCD\n"
                event = events.parse_ban_event(line)
                self.assertEqual(event.timestamp, dt.datetime(2024, 2, 29, 12, 34, 56, microseconds))
                self.assertIsNone(event.timestamp.tzinfo)
                self.assertEqual((event.jail, event.ip), ("nginx-http-auth", "2606:4700::abcd"))
        event = events.parse_ban_event("2026-09-27 12:00:00 fail2ban.actions [996]: NOTICE [sshd] Ban 8.8.8.8")
        self.assertEqual((event.jail, event.ip), ("sshd", "8.8.8.8"))

    def test_incomplete_or_malformed_records_are_not_events(self):
        """Never accept a valid timestamp/address prefix or an ambiguous jail."""
        valid = "2026-09-27 12:00:00 [sshd] Ban 8.8.8.8"
        invalid = ["", "Ban 8.8.8.8", valid.replace("Ban", "Unban"), valid.replace("Ban", "Found")]
        invalid += [valid.replace("2026-09-27 12:00:00", stamp) for stamp in (
            "2025-02-29 12:00:00", "2026-09-27 24:00:00", "2026-09-27",
            "2026-09-27 12:00:00,", "2026-09-27 12:00:00,12oops",
        )]
        invalid += [valid.replace("8.8.8.8", ip) for ip in ("", "hostname", "999.1.2.3", "2001:::1", "8.8.8.8garbage")]
        invalid += [valid.replace("[sshd]", jail) for jail in ("", "[996] [fail2ban.actions]", "[sshd] [nginx]")]
        for line in invalid:
            with self.subTest(line=line):
                self.assertIsNone(events.parse_ban_event(line))

    def test_report_selection_counts_and_compatibility(self):
        """Select rolling history, count parsed IPs, and enrich each top IP once."""
        local = ["10.1.2.3", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "fd00::1", "::1", "fe80::1"]
        lines = ["2026-09-19 23:59:59 [sshd] Ban 8.8.4.4",
                 "2026-09-20 12:00:01 [sshd] Ban 8.8.8.8",
                 "2026-09-27 12:00:00 [sshd] Ban 8.8.8.8"]
        lines += [f"2026-09-27 12:00:01 [sshd] Ban {ip}" for ip in [*local, "2606:4700::1111"]]
        parsed = [events.parse_ban_event(line) for line in lines]
        now = dt.datetime(2026, 9, 27, 12, 0, 1)
        with patch.object(reports.dt, "datetime") as clock, \
             patch.object(reports, "collect_ban_events", return_value=parsed), \
             patch.object(reports, "get_jail_list", return_value=[]), \
             patch.object(reports, "geoip") as geo:
            clock.now.return_value = now
            result = reports.build_report()
            self.assertEqual(result.period, "7d")
            self.assertEqual(result.window_start, now - dt.timedelta(hours=168))
            self.assertEqual(result.events, parsed[1:])
            self.assertEqual(result.ban_lines, lines[1:])
            self.assertEqual(result.total_bans, len(parsed) - 1)
            self.assertEqual(result.last_10_bans, parsed[-10:])
            self.assertEqual([(o.ip, o.count) for o in result.top_offenders], [("8.8.8.8", 2), ("2606:4700::1111", 1)])
            self.assertEqual(geo.lookup.call_args_list, [call("8.8.8.8"), call("2606:4700::1111")])
            all_history = reports.build_report(period="all", ignore_private=False)
            self.assertIsNone(all_history.window_start)
            self.assertEqual(all_history.events, parsed)
            self.assertEqual(sum(o.count for o in all_history.top_offenders), len(parsed))

    def test_exact_period_boundaries(self):
        """Finite windows include both endpoints; all retains even future events."""
        now = dt.datetime(2026, 9, 27, 12, 34, 56, 123456)
        tick = dt.timedelta(microseconds=1)
        for period, hours in [("1h", 1), ("24h", 24), ("7d", 168), ("30d", 720), ("all", None)]:
            with self.subTest(period=period):
                boundary = now - dt.timedelta(hours=hours or 1)
                parsed = [events.BanEvent(stamp, "sshd", "8.8.8.8", "raw")
                          for stamp in [boundary - tick, boundary, now, now + tick]]
                with patch.object(reports.dt, "datetime") as clock, \
                     patch.object(reports, "collect_ban_events", return_value=parsed) as collect, \
                     patch.object(reports, "get_jail_list", return_value=[]), \
                     patch.object(reports, "geoip"):
                    clock.now.return_value = now
                    result = reports.build_report(period=period)
                clock.now.assert_called_once_with()
                collect.assert_called_once_with(reports.LOG_CURRENT, reports.LOG_ROTATED, reports.LOG_GZ_GLOB)
                selected = parsed if hours is None else parsed[1:3]
                self.assertEqual(result.events, selected)
                self.assertEqual(result.last_10_bans, selected)
                self.assertEqual(result.total_bans, len(selected))
                self.assertEqual(result.top_offenders[0].count, len(selected))
                self.assertEqual(result.generated_at, now)
                self.assertEqual(result.window_start, boundary if hours else None)


class LogFileTests(unittest.TestCase):
    """Read real plain and compressed files through the event collector."""

    def test_chronological_order_stable_ties_and_source_failures(self):
        """Sort timestamps across rotations, retaining encounter order for ties."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            current, rotated = root / "fail2ban.log", root / "fail2ban.log.1"
            args = (str(current), str(rotated), str(root / "fail2ban.log.*.gz"))
            with self.assertRaises(FileNotFoundError):
                events.collect_ban_events(*args)
            for suffix, hour in [(".2.gz", 2), (".10.gz", 3), (".1", 1), ("", 0)]:
                path = root / f"fail2ban.log{suffix}"
                opener = gzip.open if suffix.endswith("gz") else open
                with opener(path, "wt") as stream:
                    stream.write(f"2026-09-27 0{hour}:00:00 [sshd] Ban 8.8.8.8\n")
                    stream.write(f"2026-09-27 04:00:00 [jail{hour}] Ban 1.1.1.1\n")
                    stream.write("malformed\n")
            result = events.collect_ban_events(*args)
            self.assertEqual([event.timestamp.hour for event in result], [0, 1, 2, 3, 4, 4, 4, 4])
            self.assertEqual([event.jail for event in result[-4:]], ["jail3", "jail2", "jail1", "jail0"])
            # A discovered rotation can vanish before it is opened.
            with patch.object(events.glob, "glob", return_value=[str(root / "missing.gz")]):
                self.assertEqual(len(events.collect_ban_events(*args)), 4)
            with patch.object(events.gzip, "open", side_effect=PermissionError("unreadable")):
                with self.assertRaises(PermissionError):
                    events.collect_ban_events(*args)
