"""Offline current-generation, cache, and report contracts with fake MMDB readers."""
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from offenders_geoip import GeoIP
from offenders_events import parse_ban_event

import offenders_report as report


class Reader:
    """Small DB-IP fixture with observable reads and resource lifetime."""

    def __init__(self, path):
        self.value = Path(path).read_text()
        self.calls = []
        self.closed = False

    def metadata(self):
        return SimpleNamespace(ip_version=6, database_type="DBIP")

    def get(self, ip):
        assert not self.closed
        self.calls.append(ip)
        if ip == "8.8.4.4":
            return None
        return {"country": {"names": {"en": self.value}},
                "autonomous_system_number": 15169,
                "autonomous_system_organization": "Google"}

    def close(self):
        self.closed = True


class GeoIPTests(unittest.TestCase):
    """Exercise public results using temporary stable paths and replacements."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = self.root / "app"
        self.generation = self.app / "generations" / "first"
        self.generation.mkdir(parents=True)
        (self.app / "current").symlink_to("generations/first")
        self.readers = []
        backend = SimpleNamespace(open_database=self.open_reader,
                                  InvalidDatabaseError=ValueError)
        self.patch = patch.dict("sys.modules", maxminddb=backend)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.geo = GeoIP(self.app, cache_size=2)
        self.addCleanup(self.geo.close)

    def open_reader(self, path):
        if Path(path).read_text() == "corrupt":
            raise ValueError("Invalid MMDB")
        reader = Reader(path)
        self.readers.append(reader)
        return reader

    def write(self, root, kind, value="United States"):
        path = root / f"dbip-{kind}-lite.mmdb"
        path.write_text(value)
        return path

    def test_current_pair_health_and_lookup(self):
        """Both kinds expose their stable path and usable current generation."""
        for kind in ("country", "asn"):
            self.write(self.generation, kind, "Greece")
        health = self.geo.refresh()
        self.assertTrue(all(h.state == "healthy" for h in health.values()))
        self.assertEqual(health["country"].path, str(self.app / "current/dbip-country-lite.mmdb"))
        self.assertEqual(health["country"].resolved_path, str(self.generation / "dbip-country-lite.mmdb"))
        result = self.geo.lookup("8.8.8.8")
        self.assertEqual(result.country.value, "Greece")
        self.assertEqual((result.asn.value, result.asn.organization), ("15169", "Google"))
        self.assertEqual(self.geo.lookup("8.8.4.4").country.state, "unmapped")

    def test_missing_databases_are_independent(self):
        for kind, other in (("country", "asn"), ("asn", "country")):
            with self.subTest(kind=kind):
                path = self.write(self.generation, kind)
                self.geo.refresh()
                result = self.geo.lookup("8.8.8.8")
                self.assertEqual(getattr(result, kind).state, "mapped")
                self.assertEqual(getattr(result, other).state, "unavailable")
                path.unlink()

    def test_broken_unreadable_and_broken_backend(self):
        """File/reader failures stay explicit and independent of the other kind."""
        path = self.generation / "dbip-country-lite.mmdb"
        path.symlink_to(self.root / "missing")
        self.assertEqual(self.geo.refresh()["country"].state, "missing")
        path.unlink()
        self.write(self.generation, "country", "corrupt")
        self.write(self.generation, "asn")
        health = self.geo.refresh()
        self.assertEqual(health["country"].state, "invalid")
        self.assertEqual(health["asn"].state, "healthy")
        self.write(self.generation, "country")
        with patch("offenders_geoip.os.access", return_value=False):
            self.assertEqual(self.geo.refresh()["country"].state, "unreadable")
        with patch.dict("sys.modules", maxminddb=None):
            health = self.geo.refresh()["country"]
            self.assertEqual(health.state, "reader_unavailable")
            self.assertFalse(health.reader_available)
        with patch.object(__import__('maxminddb'), "open_database", side_effect=RuntimeError("broken")):
            self.assertEqual(self.geo.refresh()["country"].state, "reader_unavailable")

    def test_reuse_normalization_lru_and_generation_switch(self):
        self.write(self.generation, "country")
        self.write(self.generation, "asn")
        self.geo.refresh()
        old_country, old_asn = self.readers
        self.geo.lookup("2001:4860:4860:0000:0000:0000:0000:8888")
        self.geo.lookup("2001:4860:4860::8888")
        self.assertEqual(old_country.calls, ["2001:4860:4860::8888"])
        self.geo.lookup("8.8.8.8")
        self.geo.lookup("8.8.4.4")
        self.geo.lookup("8.8.4.4")
        self.geo.lookup("2001:4860:4860::8888")
        self.assertEqual(len(old_country.calls), 4)
        self.geo.refresh()
        self.assertEqual(len(self.readers), 2)
        target = self.app / "generations/second"
        target.mkdir()
        country = self.write(target, "country", "Greece")
        self.write(target, "asn")
        link = self.app / "current.tmp"
        link.symlink_to("generations/second")
        os.replace(link, self.app / "current")
        self.geo.refresh()
        self.assertEqual(len(self.readers), 4)
        self.assertTrue(old_country.closed)
        self.assertTrue(old_asn.closed)
        self.assertEqual(self.geo.lookup("2001:4860:4860::8888").country.value, "Greece")
        new_asn = self.readers[-1]
        country.write_text("France")
        self.geo.refresh()
        self.assertFalse(new_asn.closed)
        self.assertEqual(self.geo.lookup("8.8.8.8").country.value, "France")
        self.geo.close()
        self.assertTrue(all(r.closed for r in self.readers))

    def test_report_preserves_values_and_structured_outcomes(self):
        self.write(self.generation, "country")
        self.write(self.generation, "asn")
        lines = ["2026-09-27 01:00:00 [sshd] Ban 8.8.8.8",
                 "2026-09-27 01:00:01 [sshd] Ban 8.8.4.4"]
        with patch.object(report, "geoip", self.geo), \
             patch.object(report, "collect_ban_events", return_value=[parse_ban_event(line) for line in lines]), \
             patch.object(report, "get_jail_list", return_value=[]), \
             patch("subprocess.run", side_effect=AssertionError("No external lookups")):
            result = report.build_report(period="all")
        self.assertEqual(result.top_offenders[0].country, "United States")
        self.assertEqual(result.top_offenders[0].asn, "15169")
        self.assertEqual(result.top_offenders[1].enrichment.country.state, "unmapped")
        self.assertEqual(result.geoip_health["country"].state, "healthy")

    def test_incomplete_records_and_read_failures_remain_distinct(self):
        self.write(self.generation, "country")
        self.write(self.generation, "asn")
        self.geo.refresh()
        country, asn = self.readers
        with patch.object(country, "get", return_value={"country": []}), \
             patch.object(asn, "get", return_value={"autonomous_system_number": "bad"}):
            result = self.geo.lookup("8.8.8.8")
            self.assertEqual(result.country.state, "unmapped")
            self.assertEqual(result.asn.state, "unmapped")
        with patch.object(country, "get", side_effect=RuntimeError("read failure")):
            result = self.geo.lookup("1.1.1.1")
            self.assertEqual(result.country.state, "unavailable")
            self.assertEqual(result.asn.state, "mapped")
        # Failures are not cached as healthy negative answers.
        self.assertEqual(self.geo.lookup("1.1.1.1").country.state, "mapped")

    def test_missing_current_ignores_flat_and_system_databases(self):
        """Valid obsolete files, including virtual system files, are never inspected."""
        (self.app / "current").unlink()
        system = self.root / "system"
        system.mkdir()
        for kind in ("country", "asn"):
            self.write(self.app, kind)
            self.write(system, kind)
        real_stat = Path.stat

        def stat(path, **kwargs):
            if path.parent == Path("/usr/share/GeoIP"):
                return real_stat(system / path.name, **kwargs)
            return real_stat(path, **kwargs)

        with patch.object(Path, "stat", autospec=True, side_effect=stat) as inspected:
            health = self.geo.refresh()
        self.assertTrue(all(h.state == "missing" for h in health.values()))
        self.assertEqual(self.readers, [])
        obsolete = {root / f"dbip-{kind}-lite.mmdb"
                    for root in (self.app, Path("/usr/share/GeoIP"))
                    for kind in ("country", "asn")}
        self.assertFalse(any(call.args[0] in obsolete for call in inspected.call_args_list))
        self.assertEqual(self.geo.lookup("8.8.8.8").country.state, "unavailable")

    def test_dangling_and_cyclic_current_are_bounded_unhealthy(self):
        """Broken current references never abort refresh or manufacture healthy data."""
        for target, state in (("missing", "missing"), ("current", "unreadable")):
            with self.subTest(target=target):
                (self.app / "current").unlink()
                (self.app / "current").symlink_to(target)
                health = self.geo.refresh()
                self.assertTrue(all(h.state == state for h in health.values()))
                self.assertTrue(all(len(h.detail) <= 240 for h in health.values()))
                self.assertEqual(self.geo.lookup("8.8.8.8").country.state, "unavailable")

    def test_corrupt_lookup_stays_unavailable_until_valid_generation(self):
        """Detected corruption closes the reader; unchanged refresh cannot resurrect it."""
        self.write(self.generation, "country")
        self.write(self.generation, "asn")
        self.geo.refresh()
        with patch.object(self.readers[0], "get", side_effect=ValueError("corrupt data")):
            self.assertEqual(self.geo.lookup("8.8.8.8").country.state, "unavailable")
        self.assertTrue(self.readers[0].closed)
        self.assertEqual(self.geo.health()["country"].state, "invalid")
        self.assertEqual(self.geo.health()["asn"].state, "healthy")
        self.assertEqual(self.geo.refresh()["country"].state, "invalid")
        self.assertEqual(self.geo.lookup("8.8.8.8").country.state, "unavailable")
        target = self.app / "generations/recovered"
        target.mkdir()
        self.write(target, "country", "Greece")
        self.write(target, "asn")
        link = self.app / "current.tmp"
        link.symlink_to("generations/recovered")
        os.replace(link, self.app / "current")
        self.assertEqual(self.geo.refresh()["country"].state, "healthy")
        self.assertEqual(self.geo.lookup("8.8.8.8").country.value, "Greece")
