"""Offline lifecycle contracts through the engine, readers, and CLI."""
import datetime as dt
import gzip
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.error

import offenders_geoip as geo
import offenders_geoip_cli as cli
import offenders_geoip_update as updater
from test_geoip import Reader


class StagedReader(Reader):
    """Minimal reader contract: role metadata plus iterable decoded records."""

    def metadata(self):
        return SimpleNamespace(ip_version=6, database_type=self.value)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __iter__(self):
        yield "8.8.8.0/24", self.get("8.8.8.8")


class LifecycleTests(unittest.TestCase):
    """Combine failure modes around preservation, activation, and policy seams."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "data"
        self.now = dt.datetime(2026, 9, 27, tzinfo=dt.timezone.utc).timestamp()
        self.urls = []
        backend = SimpleNamespace(open_database=StagedReader, InvalidDatabaseError=ValueError)
        reader_patch = patch.dict("sys.modules", maxminddb=backend)
        reader_patch.start()
        self.addCleanup(reader_patch.stop)

    def fetch(self, url):
        self.urls.append(url)
        role = "country" if "country" in url else "asn"
        response = io.BytesIO(gzip.compress(f"DBIP-{role}".encode()))
        response.status, response.headers = 200, {}
        return response

    def run_update(self, **kwargs):
        return updater.update(self.root, opener=kwargs.pop("opener", self.fetch),
                              now=kwargs.pop("now", self.now), **kwargs)

    def test_pair_activation_refresh_fallback_and_retention(self):
        legacy = Path(self.temp.name) / "legacy"
        legacy.mkdir()
        for role in updater.KINDS:
            (legacy / f"dbip-{role}-lite.mmdb").write_text("legacy")
        service = geo.GeoIP(self.root, legacy)
        self.addCleanup(service.close)
        self.assertTrue(all(h.fallback for h in service.refresh().values()))
        self.assertEqual(self.run_update(), "2026-09")  # Manual while auto is off.
        first = (self.root / "current").resolve()
        self.assertTrue(all(h.source == "app-managed" for h in service.refresh().values()))
        self.assertEqual(service.lookup("8.8.8.8").country.value, "DBIP-country")
        incomplete = self.root / "generations" / ("2026-01-" + "a" * 32)
        incomplete.mkdir()
        (incomplete / "dbip-country-lite.mmdb").write_text("incomplete")
        self.run_update()
        second = (self.root / "current").resolve()
        self.assertNotEqual(first, second)
        self.assertTrue(first.exists())

        def unpublished(url):
            if "asn-lite-2026-09" in url:
                raise urllib.error.HTTPError(url, 404, "unpublished", {}, None)
            return self.fetch(url)

        self.assertEqual(self.run_update(opener=unpublished), "2026-08")
        self.assertTrue(second.exists())
        self.assertFalse(first.exists())
        self.assertTrue(incomplete.exists())
        self.assertEqual(len(list((self.root / "generations").iterdir())), 3)
        self.assertTrue(all("2026-08" in url for url in self.urls[-2:]))
        self.assertTrue(all(p.read_text() == "legacy" for p in legacy.iterdir()))
        self.assertFalse(list(self.root.glob(".staging-*")))

    def test_update_recovers_cyclic_current_from_legacy_fallback(self):
        """Explicit update repairs a broken managed link without touching legacy."""
        self.root.mkdir()
        (self.root / "current").symlink_to("current")
        legacy = Path(self.temp.name) / "legacy"
        legacy.mkdir()
        for role in updater.KINDS:
            (legacy / f"dbip-{role}-lite.mmdb").write_text("legacy")
        service = geo.GeoIP(self.root, legacy)
        self.addCleanup(service.close)
        self.assertTrue(all(health.fallback for health in service.refresh().values()))
        self.assertEqual(service.lookup("8.8.8.8").country.value, "legacy")

        self.assertEqual(self.run_update(), "2026-09")

        active = (self.root / "current").resolve(strict=True)
        self.assertEqual(active.parent, self.root / "generations")
        self.assertTrue(all(health.source == "app-managed"
                            for health in service.refresh().values()))
        self.assertEqual(service.lookup("8.8.8.8").country.value, "DBIP-country")
        self.assertTrue(all(path.read_text() == "legacy" for path in legacy.iterdir()))

    def test_failure_matrix_preserves_current_and_cleans_staging(self):
        self.run_update()
        active = (self.root / "current").resolve()
        original = {p.name: p.read_bytes() for p in active.iterdir()}
        cases = ("timeout", "http", "compressed", "decompressed", "gzip",
                 "truncated", "length", "mmdb", "role", "activation")
        for case in cases:
            with self.subTest(case=case):
                def broken(url):
                    if "country" in url:
                        return self.fetch(url)  # One succeeds, the other fails.
                    if case == "timeout":
                        raise TimeoutError("read timed out")
                    response = self.fetch(url)
                    if case == "http":
                        response.status = 503
                    if case in ("gzip", "mmdb", "role", "truncated"):
                        payload = {"gzip": b"not gzip", "mmdb": gzip.compress(b""),
                                   "role": gzip.compress(b"DBIP-country"),
                                   "truncated": gzip.compress(b"DBIP-asn")[:-4]}[case]
                        response = io.BytesIO(payload)
                        response.status, response.headers = 200, {}
                    if case == "length":
                        response.headers = {"Content-Length": "9999"}
                    return response

                with patch.object(updater, "MAX_COMPRESSED", 1 if case == "compressed" else 1000), \
                     patch.object(updater, "MAX_DECOMPRESSED", 1 if case == "decompressed" else 1000):
                    if case == "activation":
                        real_replace = updater.os.replace

                        def fail_switch(source, destination):
                            if Path(destination).name == "current":
                                raise OSError("switch refused")
                            return real_replace(source, destination)

                        with patch.object(updater.os, "replace", side_effect=fail_switch):
                            with self.assertRaises(updater.UpdateError):
                                self.run_update(opener=broken)
                    else:
                        with self.assertRaises(updater.UpdateError):
                            self.run_update(opener=broken)
                self.assertEqual((self.root / "current").resolve(), active)
                self.assertEqual({p.name: p.read_bytes() for p in active.iterdir()}, original)
                self.assertFalse(list(self.root.glob(".staging-*")))
                self.assertFalse((self.root / "current.tmp").exists())
                self.assertEqual(list((self.root / "generations").iterdir()), [active])
                self.assertTrue(updater.read_state(self.root)["outcome"].startswith("failed:"))

    def test_read_only_status_xdg_policy_due_and_writer_refusal(self):
        with patch.dict("os.environ", XDG_DATA_HOME=""), patch.object(Path, "home", return_value=self.root):
            self.assertEqual(geo.resolve_data_root(), self.root / ".local/share/offenders/geoip")
        with patch.dict("os.environ", XDG_DATA_HOME=str(self.root)):
            self.assertEqual(geo.resolve_data_root(), self.root / "offenders/geoip")
        with patch.object(cli, "resolve_data_root", return_value=self.root), \
             patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("network")), \
             patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(cli.main(["status"]), 0)
            self.assertFalse(json.loads(output.getvalue())["auto"])
            self.assertFalse(self.root.exists())
            self.assertIsNone(self.run_update(automatic=True))
            self.assertEqual(self.urls, [])
            cli.main(["auto", "on"])
            self.assertTrue(updater.automatic_due(updater.read_state(self.root), self.now))
            self.run_update(automatic=True)
            self.assertEqual(len(self.urls), 2)
            self.assertIsNone(self.run_update(automatic=True, now=self.now + 86399))
            self.assertEqual(len(self.urls), 2)
            self.assertTrue(updater.automatic_due(updater.read_state(self.root), self.now + 86400))
            cli.main(["auto", "off"])
            self.assertFalse(updater.automatic_due(updater.read_state(self.root), self.now + 90000))
            with updater.writer_lock(self.root):
                with self.assertRaisesRegex(updater.UpdateError, "lock"):
                    self.run_update()
            self.assertEqual(len(self.urls), 2)
        with patch.object(cli, "resolve_data_root", return_value=self.root), \
             patch.object(cli, "update", side_effect=updater.UpdateError("offline")), \
             patch("sys.stderr", new_callable=io.StringIO) as error:
            self.assertEqual(cli.main(["update"]), 1)
            self.assertIn("offline", error.getvalue())
