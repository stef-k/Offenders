"""Pure-data contracts for one report's selected-IP snapshot."""
import datetime as dt
import unittest
from dataclasses import FrozenInstanceError, replace
from unittest.mock import Mock

from offenders_events import BanEvent
from offenders_fail2ban import JailStatus
from offenders_geoip import Enrichment, LookupResult
from offenders_ip import project_ip
from offenders_report import Offender, Report


NOW = dt.datetime(2026, 9, 27, 12)
UNMAPPED = Enrichment(LookupResult("unmapped"), LookupResult("unmapped"))


def report(events=(), statuses=(), top=()):
    """Build a committed report without host or UI dependencies."""
    return Report(NOW, "24h", NOW - dt.timedelta(days=1),
                  list(events), list(top), list(statuses))


class IPProjectionTests(unittest.TestCase):
    """Keep history, live membership, and structured enrichment independent."""

    def test_history_counts_stable_recent_events_and_snapshot(self):
        """Count duplicates, sort jail ties, and retain ten original records."""
        events = [BanEvent(NOW - dt.timedelta(minutes=i // 2), jail,
                           "8.8.8.8", f"opaque record {i}")
                  for i, jail in enumerate(["z", "a", "b"] * 4)]
        events.append(events[0])
        source = report(events + [BanEvent(NOW, "other", "1.1.1.1", "")],
                        [JailStatus("z", 0, 0, 99, 500, ("1.1.1.1",))])
        lookup = Mock(return_value=UNMAPPED)
        result = project_ip(source, "8.8.8.8", lookup=lookup)
        lookup.assert_called_once_with("8.8.8.8")
        self.assertEqual((result.period, result.generated_at), ("24h", NOW))
        self.assertEqual(result.total_bans, 13)
        self.assertEqual((result.first_seen, result.last_seen),
                         (NOW - dt.timedelta(minutes=5), NOW))
        self.assertEqual(result.jail_counts, (("z", 5), ("a", 4), ("b", 4)))
        self.assertEqual(result.distinct_jail_count, 3)
        expected = sorted(events, key=lambda event: event.timestamp, reverse=True)[:10]
        self.assertEqual(result.recent_events, tuple(expected))
        for actual, original in zip(result.recent_events, expected):
            self.assertIs(actual, original)
        self.assertFalse(result.currently_banned)
        self.assertEqual(result.current_jails, ())
        source.events.clear()
        source.jail_statuses.clear()
        self.assertEqual(result.total_bans, 13)
        with self.assertRaises(FrozenInstanceError):
            result.ip = "1.1.1.1"

    def test_current_only_ipv6_and_local_history(self):
        """Normalize selection, preserve daemon order, and ignore counter skew."""
        selected = "2606:4700:0:0:0:0:0:ABCD"
        statuses = [JailStatus(name, 0, 0, count, 99, ips) for name, count, ips in (
            ("z", 0, ("2606:4700::abcd",)),
            ("absent", 10, ("1.1.1.1",)),
            ("a", 7, (selected,)),
        )]
        lookup = Mock(return_value=UNMAPPED)
        result = project_ip(report(statuses=statuses), selected, lookup=lookup)
        self.assertEqual(result.ip, "2606:4700::abcd")
        lookup.assert_called_once_with(result.ip)
        self.assertTrue(result.currently_banned)
        self.assertEqual(result.current_jails, ("z", "a"))
        self.assertEqual((result.total_bans, result.distinct_jail_count), (0, 0))
        self.assertEqual((result.first_seen, result.last_seen), (None, None))
        self.assertEqual((result.jail_counts, result.recent_events), ((), ()))
        for ip in ("127.0.0.1", "10.0.0.1", "fe80::1", "::1", result.ip):
            with self.subTest(ip=ip):
                event = BanEvent(NOW, "sshd", ip, "not reparsed")
                item = project_ip(report([event]), ip, lookup=lookup)
                self.assertEqual(item.total_bans, 1)
                self.assertEqual((item.first_seen, item.last_seen), (NOW, NOW))
                self.assertFalse(item.currently_banned)

    def test_enrichment_reuse_and_single_fallback_preserve_outcomes(self):
        """Reuse every non-null outcome; otherwise call the local seam once."""
        outcomes = [UNMAPPED,
                    Enrichment(LookupResult("mapped", "Greece"),
                               LookupResult("mapped", "123", "Example")),
                    Enrichment(LookupResult("unavailable", detail="missing"),
                               LookupResult("unmapped", organization="Example"))]
        for outcome in outcomes:
            for reuse in (True, False):
                with self.subTest(outcome=outcome, reuse=reuse):
                    top = Offender("2606:4700::abcd", 1, "", "", "", outcome)
                    if not reuse:
                        top = replace(top, enrichment=None)
                    lookup = Mock(return_value=outcome)
                    result = project_ip(report(top=[top]),
                                        "2606:4700:0:0:0:0:0:ABCD", lookup=lookup)
                    self.assertIs(result.enrichment, outcome)
                    if reuse:
                        lookup.assert_not_called()
                    else:
                        lookup.assert_called_once_with(result.ip)

    def test_invalid_input_raises_before_lookup(self):
        """Invalid caller input must not become a fabricated empty snapshot."""
        lookup = Mock()
        with self.assertRaises(ValueError):
            project_ip(report(), "not-an-ip", lookup=lookup)
        lookup.assert_not_called()
