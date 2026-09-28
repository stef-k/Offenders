"""Explicit one-snapshot CSV export without starting the Textual application."""
import argparse
import sys

from offenders_export import export_report
from offenders_report import DEFAULT_PERIOD, PERIODS, build_report


def main(argv=None):
    """Acquire exactly once and report bounded failures without traceback output."""
    parser = argparse.ArgumentParser(prog="offenders export")
    parser.add_argument("--period", choices=PERIODS, default=DEFAULT_PERIOD)
    parser.add_argument("--output-dir", help="Export root (default: ~/offenders-exports)")
    args = parser.parse_args(argv)
    try:
        report = build_report(period=args.period)
        path = export_report(report, args.output_dir)
    except Exception as error:
        detail = " ".join(str(error).split())[:240]
        print(f"Export failed: {detail or type(error).__name__}", file=sys.stderr)
        return 1
    print(f"Export complete: {path}")
    return 0
