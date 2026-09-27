"""Full-event projection conservation, enrichment ownership, and loaded filtering."""
from dataclasses import replace
import unittest
from unittest.mock import Mock

from offenders_aggregate import aggregate_report, filter_aggregates
from offenders_events import BanEvent
from offenders_geoip import Enrichment, LookupResult
from offenders_report import Offender
from test_refresh import report


def source():
    """Keep top-N narrower than history, including private and IPv6 addresses."""
    base = report()
    mapped = Enrichment(LookupResult("mapped", "GR"), LookupResult("mapped", "123", "Straße"))
    facts = {
        "8.8.8.8": mapped,
        "1.1.1.1": mapped,
        "127.0.0.1": Enrichment(LookupResult("unmapped"), LookupResult("unavailable")),
        "::1": Enrichment(LookupResult("unavailable"), LookupResult("unmapped", organization="partial")),
    }
    events = [BanEvent(base.generated_at, "OldJail", ip, "")
              for ip in ["8.8.8.8", "8.8.8.8", "1.1.1.1", "127.0.0.1", "::1"]]
    return replace(base, events=events, top_offenders=[
        Offender("8.8.8.8", 2, "GR", "123", "Straße", mapped)]), facts


class ProjectionTests(unittest.TestCase):
    """Assert contract facts directly rather than internal accumulator details."""

    def test_counts_states_reuse_order_and_visibility(self):
        data, facts = source()
        lookup = Mock(side_effect=facts.__getitem__)
        result = aggregate_report(data, lookup)
        self.assertCountEqual([call.args[0] for call in lookup.call_args_list],
                              ["1.1.1.1", "127.0.0.1", "::1"])
        for rows in (result.asn, result.country):
            self.assertEqual(sum(row.bans for row in rows), len(data.events))
            self.assertEqual([(r.bans, r.distinct_ips) for r in rows], [(3, 2), (1, 1), (1, 1)])
            self.assertEqual([r.identity[0] for r in rows], ["mapped", "unavailable", "unmapped"])
            for query in ("  STRASSE ", "oldj", "8.8", "as123", "GR"):
                visible = filter_aggregates(rows, query)
                self.assertIn(rows[0], visible)
                self.assertEqual(visible[0].bans, 3)
            self.assertEqual(filter_aggregates(rows, "absent"), ())
            self.assertEqual(filter_aggregates(rows, "  "), rows)
        self.assertEqual(result.asn[0].value, "AS123")
        self.assertEqual([r.organization for r in result.asn[1:]], ["", ""])
        reverse = replace(data, events=list(reversed(data.events)))
        self.assertEqual(aggregate_report(reverse, facts.__getitem__), result)
        self.assertEqual(aggregate_report(replace(data, events=[]), lookup).asn, ())
