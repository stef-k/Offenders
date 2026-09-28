"""CSV compatibility, lossless report projection and atomic publication contracts."""
import csv
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from offenders_export import SCHEMAS, TEXT_POLICY, export_report, safe_text
from offenders_geoip import Enrichment, LookupResult
from test_refresh import report


class ExportTests(unittest.TestCase):
    """Exercise real files with normalized snapshots and injected write failures."""

    def read(self, path, name):
        """Read exported values through the public CSV format."""
        with (path / name).open(encoding="utf-8", newline="") as stream:
            return list(csv.reader(stream))

    def test_populated_bundle_and_collisions(self):
        source = report(12)
        text = 'Ελλάδα, "quoted"\nnext'
        mapped = replace(source.top_offenders[0], enrichment=Enrichment(
            LookupResult("mapped", text), LookupResult("mapped", "AS123", "\t=evil")))
        missing = replace(mapped, enrichment=Enrichment(LookupResult("unmapped"), LookupResult("unavailable")))
        source = replace(source, top_offenders=[mapped, missing, source.top_offenders[0]],
                         jail_statuses=[replace(source.jail_statuses[0], bantime=-1, findtime=0,
                                                backend="@backend", filter_name='sshd')])
        with tempfile.TemporaryDirectory() as root, patch('subprocess.run') as shell:
            paths = [export_report(source, root) for _ in range(3)]
            self.assertEqual([p.name for p in paths], [
                'offenders-7d-2026_09_27_T121200', 'offenders-7d-2026_09_27_T121200-2',
                'offenders-7d-2026_09_27_T121200-3'])
            path = paths[0]
            self.assertTrue(path.is_absolute())
            self.assertEqual({p.name for p in path.iterdir()}, set(SCHEMAS))
            for name, header in SCHEMAS.items():
                self.assertEqual(self.read(path, name)[0], list(header))
                self.assertEqual((path / name).stat().st_mode & 0o777, 0o600)
                self.assertEqual((path / name).read_bytes(), (paths[1] / name).read_bytes())
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)
            meta = self.read(path, 'report.csv')[1]
            self.assertEqual(meta, ['1', '7d', source.generated_at.isoformat(), '', '12', '3', '1', TEXT_POLICY])
            top = self.read(path, 'top-offenders.csv')[1:]
            self.assertEqual(top[0], ['1', '12', '8.8.8.8', 'mapped', text, 'mapped', 'AS123', "'\t=evil"])
            self.assertEqual(top[1][3:], ['unmapped', '', 'unavailable', '', ''])
            self.assertEqual(top[2][3:], ['unavailable', '', 'unavailable', '', ''])
            jail = self.read(path, 'jail-status.csv')[1]
            self.assertEqual(jail, ['sshd', '0', '0', '12', '12', '-1', '0', '', "'@backend", 'sshd', '8.8.8.8'])
            events = self.read(path, 'ban-events.csv')[1:]
            self.assertEqual(events, [[e.timestamp.isoformat(), e.jail, e.ip] for e in source.events])
            self.assertEqual(len(events), 12)
            shell.assert_not_called()

    def test_empty_all_and_existing_empty_directory(self):
        source = replace(report(), period='all', events=[], top_offenders=[], jail_statuses=[])
        with tempfile.TemporaryDirectory() as root:
            reserved = Path(root) / 'offenders-all-2026_09_27_T120200'
            reserved.mkdir()
            path = export_report(source, root)
            self.assertEqual(path.name, reserved.name + '-2')
            self.assertEqual(list(reserved.iterdir()), [])
            self.assertEqual(self.read(path, 'report.csv')[1][1:5], ['all', source.generated_at.isoformat(), '', '0'])
            for name in list(SCHEMAS)[1:]:
                self.assertEqual(self.read(path, name), [list(SCHEMAS[name])])

    def test_formula_policy_and_numeric_values(self):
        for prefix in ('', ' ', '\t', '\r', '\n', '\x00', '\u2003\x01 '):
            for formula in ('=1', '+1', '-1', '@SUM(A1)'):
                text = prefix + formula
                self.assertEqual(safe_text(text), "'" + text)
        for normal in ('normal', 'é, "\ntext', "'=already", '  normal', '', -12, 0, None):
            self.assertEqual(safe_text(normal), normal)

    def test_failures_never_publish_partial_bundle(self):
        with tempfile.TemporaryDirectory() as root:
            real_open = __import__('os').open

            def fail_second(path, *args, **kwargs):
                if str(path).endswith('top-offenders.csv'):
                    raise PermissionError('denied')
                return real_open(path, *args, **kwargs)

            with patch('offenders_export.os.open', side_effect=fail_second):
                with self.assertRaises(PermissionError):
                    export_report(report(), root)
            self.assertEqual(list(Path(root).iterdir()), [])
            with patch('offenders_export._publish', side_effect=OSError('rename failed')):
                with self.assertRaises(OSError):
                    export_report(report(), root)
            self.assertEqual(list(Path(root).iterdir()), [])
            bad = Path(root) / 'file'
            bad.write_text('retained')
            with self.assertRaises(FileExistsError):
                export_report(report(), bad)
            self.assertEqual(bad.read_text(), 'retained')
            with self.assertRaises(ValueError):
                export_report(replace(report(), period='../escape'), root)
