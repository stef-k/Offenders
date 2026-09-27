"""Offline characterization of the dashboard's log, IP, and jail contracts."""

import datetime as dt
import gzip
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import offenders_report as offenders


class ParsingTests(unittest.TestCase):
    """Exercise parsing directly without starting the UI or enrichment tools."""

    def test_ban_recognition_and_ip_normalization(self):
        """Accept Ban events for both families, preserving repeated events."""
        lines = [
            "2026-09-27 12:00:00,123 fail2ban.actions [996]: NOTICE [sshd] Ban 8.8.8.8",
            "2026-09-27 12:00:01 fail2ban.actions [996]: NOTICE [sshd] Ban 2606:4700:0000:0000:0000:0000:0000:ABCD",
            "2026-09-27 12:00:02 fail2ban.actions [996]: NOTICE [sshd] Ban 8.8.8.8",
        ]
        self.assertTrue(all(offenders.is_real_ban_line(line) for line in lines))
        self.assertEqual(offenders.extract_ips(lines), ["8.8.8.8", "2606:4700::abcd", "8.8.8.8"])

    def test_non_bans_and_invalid_addresses_are_ignored(self):
        """Found, Unban, missing addresses, and invalid tokens are not bans."""
        for line in ["", "Found 8.8.8.8", "Unban 8.8.8.8", "Ban", "Ban hostname", "Ban 999.1.2.3", "Ban 2001:::1"]:
            with self.subTest(line=line):
                self.assertFalse(offenders.is_real_ban_line(line))
                self.assertEqual(offenders.extract_ips([line]), [])

    def test_private_loopback_and_link_local_addresses_are_filtered(self):
        """Keep public addresses while excluding local addresses in both families."""
        local = ["10.1.2.3", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "fd00::1", "::1", "fe80::1"]
        self.assertEqual(
            offenders.filter_private_ips(["8.8.8.8", *local, "invalid", "2606:4700::1111", "8.8.8.8"]),
            ["8.8.8.8", "2606:4700::1111", "8.8.8.8"],
        )

    def test_log_dates(self):
        """Parse valid calendar dates and reject absent or impossible dates."""
        self.assertEqual(offenders.parse_log_date("2024-02-29 23:59:59 Ban 8.8.8.8"), dt.date(2024, 2, 29))
        for line in ["", "garbage", "2025-02-29 Ban 8.8.8.8"]:
            with self.subTest(line=line):
                self.assertIsNone(offenders.parse_log_date(line))

    def test_lookback_includes_entire_cutoff_day(self):
        """Lookback uses an inclusive calendar date, not a rolling hour window."""
        lines = [
            "2026-09-19 23:59:59 Ban 8.8.8.8\n",
            "2026-09-20 00:00:00 Ban 8.8.8.8\n",
            "2026-09-27 12:00:00 Ban 1.1.1.1\n",
            "unknown-date Ban 8.8.4.4\n",
            "2026-09-27 12:00:00 Unban 1.1.1.1\n",
        ]
        with patch.object(offenders.dt, "datetime") as clock, patch.object(offenders, "iter_unified_log_stream", return_value=lines):
            # Use a real date while replacing only the wall-clock access.
            clock.now.return_value.date.return_value = dt.date(2026, 9, 27)
            selected, cutoff = offenders.collect_ban_lines(7)
            self.assertEqual(cutoff, dt.date(2026, 9, 20))
            self.assertEqual(selected, [line.rstrip("\n") for line in lines[1:3]])
            selected, cutoff = offenders.collect_ban_lines(0)
            self.assertIsNone(cutoff)
            self.assertEqual(selected, [line.rstrip("\n") for line in lines[:4]])

    def test_jail_and_table_fields(self):
        """Skip process/logger brackets and expose normalized IPs in table rows."""
        self.assertEqual(
            offenders._parse_ban_line_for_table("2026-09-27 12:34:56,789 [fail2ban.actions] [996]: NOTICE [nginx-http-auth] Ban 2606:4700:0:0:0:0:0:ABCD"),
            ("2026-09-27", "12:34:56", "nginx-http-auth", "2606:4700::abcd"),
        )
        self.assertEqual(offenders._parse_ban_line_for_table("Ban 8.8.8.8"), ("", "", "", "8.8.8.8"))


class LogFileTests(unittest.TestCase):
    """Read real temporary plain and compressed logs through the product stream."""

    def test_rotation_order_and_missing_optional_files(self):
        """Read numeric gzip rotations oldest first, then .1 and current."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.multiple(offenders, LOG_CURRENT=str(root / "fail2ban.log"), LOG_ROTATED=str(root / "fail2ban.log.1"), LOG_GZ_GLOB=str(root / "fail2ban.log.*.gz")):
                self.assertEqual(list(offenders.iter_unified_log_stream()), [])
                for number in [2, 10, 3]:
                    with gzip.open(root / f"fail2ban.log.{number}.gz", "wt") as stream:
                        stream.write(f"rotation {number}\n")
                self.assertEqual(list(offenders.iter_unified_log_stream()), ["rotation 10\n", "rotation 3\n", "rotation 2\n"])
                (root / "fail2ban.log.1").write_text("rotated first\nrotated second\n", encoding="utf-8")
                (root / "fail2ban.log").write_text("current\n", encoding="utf-8")
                self.assertEqual(list(offenders.iter_unified_log_stream()), ["rotation 10\n", "rotation 3\n", "rotation 2\n", "rotated first\n", "rotated second\n", "current\n"])
