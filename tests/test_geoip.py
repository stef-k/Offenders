"""Offline source, lifetime, cache, and report contracts with fake MMDB readers."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from offenders_geoip import GeoIP
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
        self.app, self.legacy = self.root / "app", self.root / "legacy"
        self.app.mkdir()
        self.legacy.mkdir()
        self.readers = []
        backend = SimpleNamespace(open_database=self.open_reader,
                                  InvalidDatabaseError=ValueError)
        self.patch = patch.dict("sys.modules", maxminddb=backend)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.geo = GeoIP(self.app, self.legacy, cache_size=2)
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

    def test_preference_fallback_and_independent_health(self):
        for kind in ("country", "asn"):
            self.write(self.legacy, kind)
        health = self.geo.refresh()
        self.assertTrue(all(h.fallback for h in health.values()))
        self.assertEqual(health["country"].candidates[0].state, "missing")
        self.write(self.app, "country", "corrupt")
        self.write(self.app, "asn")
        health = self.geo.refresh()
        self.assertEqual(health["country"].candidates[0].state, "invalid")
        self.assertEqual(health["country"].source, "legacy-system")
        self.assertEqual(health["asn"].source, "app-managed")
        self.write(self.app, "country", "Greece")
        health = self.geo.refresh()
        self.assertEqual(health["country"].source, "app-managed")
        result = self.geo.lookup("8.8.8.8")
        self.assertEqual(result.country.value, "Greece")
        self.assertEqual((result.asn.value, result.asn.organization), ("15169", "Google"))
        self.assertEqual(self.geo.lookup("8.8.4.4").country.state, "unmapped")

    def test_missing_databases_are_independent(self):
        for kind, other in (("country", "asn"), ("asn", "country")):
            with self.subTest(kind=kind):
                path = self.write(self.app, kind)
                self.geo.refresh()
                result = self.geo.lookup("8.8.8.8")
                self.assertEqual(getattr(result, kind).state, "mapped")
                self.assertEqual(getattr(result, other).state, "unavailable")
                path.unlink()

    def test_broken_unreadable_and_broken_backend(self):
        path = self.app / "dbip-country-lite.mmdb"
        path.symlink_to(self.root / "missing")
        self.assertEqual(self.geo.refresh()["country"].candidates[0].state, "broken_symlink")
        path.unlink()
        self.write(self.app, "country")
        with patch("offenders_geoip.os.access", return_value=False):
            self.assertEqual(self.geo.refresh()["country"].candidates[0].state, "unreadable")
        with patch.dict("sys.modules", maxminddb=None):
            health = self.geo.refresh()["country"].candidates[0]
            self.assertEqual(health.state, "reader_unavailable")
            self.assertFalse(health.reader_available)
        with patch.object(__import__('maxminddb'), "open_database", side_effect=RuntimeError("broken")):
            self.assertEqual(self.geo.refresh()["country"].candidates[0].state, "reader_unavailable")

    def test_reuse_normalization_lru_and_generation_switch(self):
        country = self.write(self.app, "country")
        self.write(self.app, "asn")
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
        target = self.root / "new-country"
        target.write_text("Greece")
        country.unlink()
        country.symlink_to(target)
        self.geo.refresh()
        self.assertEqual(len(self.readers), 3)
        self.assertTrue(old_country.closed)
        self.assertFalse(old_asn.closed)
        before = len(old_asn.calls)
        self.assertEqual(self.geo.lookup("2001:4860:4860::8888").country.value, "Greece")
        self.assertEqual(len(old_asn.calls), before)
        target.write_text("France")
        self.geo.refresh()
        self.assertEqual(self.geo.lookup("8.8.8.8").country.value, "France")
        self.geo.close()
        self.assertTrue(all(r.closed for r in self.readers))

    def test_report_preserves_values_and_structured_outcomes(self):
        self.write(self.app, "country")
        self.write(self.app, "asn")
        lines = ["2026-09-27 01:00:00 [sshd] Ban 8.8.8.8",
                 "2026-09-27 01:00:01 [sshd] Ban 8.8.4.4"]
        with patch.object(report, "geoip", self.geo), \
             patch.object(report.os.path, "isfile", return_value=True), \
             patch.object(report, "collect_ban_lines", return_value=(lines, None)), \
             patch.object(report, "get_jail_list", return_value=[]), \
             patch("subprocess.run", side_effect=AssertionError("No external lookups")):
            result = report.build_report()
        self.assertEqual(result.top_offenders[0].country, "United States")
        self.assertEqual(result.top_offenders[0].asn, "15169")
        self.assertEqual(result.top_offenders[1].enrichment.country.state, "unmapped")
        self.assertEqual(result.geoip_health["country"].source, "app-managed")

    def test_incomplete_records_and_read_failures_remain_distinct(self):
        self.write(self.app, "country")
        self.write(self.app, "asn")
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

    def test_xdg_root_and_symlink_retarget(self):
        with patch.dict("os.environ", XDG_DATA_HOME=str(self.root)):
            data = self.root / "offenders/geoip"
            data.mkdir(parents=True)
            stable = data / "dbip-country-lite.mmdb"
            first = self.root / "first"
            second = self.root / "second"
            first.write_text("France")
            second.write_text("Greece")
            stable.symlink_to(first)
            service = GeoIP(legacy_root=self.legacy)
            self.addCleanup(service.close)
            service.refresh()
            self.assertEqual(service.lookup("8.8.8.8").country.value, "France")
            stable.unlink()
            stable.symlink_to(second)
            health = service.refresh()["country"].candidates[0]
            self.assertTrue(health.is_symlink)
            self.assertEqual(health.resolved_path, str(second))
            self.assertEqual(service.lookup("8.8.8.8").country.value, "Greece")

    def test_corrupt_data_section_is_unhealthy_and_allows_fallback(self):
        preferred = self.write(self.app, "country")
        self.write(self.legacy, "country", "France")
        self.geo.refresh()
        with patch.object(self.readers[0], "get", side_effect=ValueError("corrupt data")):
            self.assertEqual(self.geo.lookup("8.8.8.8").country.state, "unavailable")
        health = self.geo.refresh()["country"]
        self.assertEqual(health.candidates[0].state, "invalid")
        self.assertTrue(health.fallback)
        self.assertEqual(self.geo.lookup("8.8.8.8").country.value, "France")
        preferred.write_text("Greece")
        self.assertEqual(self.geo.refresh()["country"].source, "app-managed")
        self.assertEqual(self.geo.lookup("8.8.8.8").country.value, "Greece")
