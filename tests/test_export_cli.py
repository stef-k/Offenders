"""Headless dispatch acquires one fresh snapshot and shares the CSV exporter."""
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import offenders
from offenders_report import DEFAULT_PERIOD, PERIODS
from test_refresh import report


class ExportCLITests(unittest.TestCase):
    """No application construction, supplemental acquisition, or real host I/O."""

    def test_periods_and_destination(self):
        for period in (None, *PERIODS):
            with self.subTest(period=period), tempfile.TemporaryDirectory() as root:
                source = report()
                args = ['export', '--output-dir', root]
                if period is not None:
                    args.extend(['--period', period])
                output = StringIO()
                with patch('offenders_export_cli.build_report', return_value=source) as build, \
                     patch('offenders.OffendersApp') as app, redirect_stdout(output):
                    self.assertEqual(offenders.main(args), 0)
                build.assert_called_once_with(period=period or DEFAULT_PERIOD)
                app.assert_not_called()
                path = next(Path(root).iterdir())
                self.assertEqual(output.getvalue(), f'Export complete: {path}\n')
                self.assertEqual(len(list(path.iterdir())), 4)

    def test_default_destination_and_exact_snapshot(self):
        source = report()
        with patch('offenders_export_cli.build_report', return_value=source) as build, \
             patch('offenders_export_cli.export_report', return_value=Path('/tmp/exact')) as export, \
             patch('offenders.OffendersApp') as app, redirect_stdout(StringIO()):
            self.assertEqual(offenders.main(['export']), 0)
        build.assert_called_once_with(period=DEFAULT_PERIOD)
        self.assertIs(export.call_args.args[0], source)
        self.assertIsNone(export.call_args.args[1])
        app.assert_not_called()

    def test_acquisition_and_export_failures_are_bounded(self):
        with tempfile.TemporaryDirectory() as root:
            for stage in ('build_report', 'export_report'):
                error = StringIO()
                with patch('offenders_export_cli.build_report', return_value=report()), \
                     patch(f'offenders_export_cli.{stage}', side_effect=OSError('bad\n' * 200)), \
                     redirect_stderr(error), redirect_stdout(StringIO()) as output:
                    self.assertEqual(offenders.main(['export', '--output-dir', root]), 1)
                self.assertEqual(output.getvalue(), '')
                self.assertLess(len(error.getvalue()), 260)
                self.assertEqual(len(error.getvalue().splitlines()), 1)
                self.assertEqual(list(Path(root).iterdir()), [])
