#!/usr/bin/env python3
"""Deprecated updater entrypoint: use `offenders geoip update` instead.

The old system-target/cron options are retired. This wrapper shares the rootless
XDG lifecycle and never writes the legacy /usr/share/GeoIP installation.
"""
import sys

from offenders_geoip_cli import main as geoip_main


def main():
    """Delegate to the single update engine, rejecting retired options."""
    return geoip_main(["update", *sys.argv[1:]])


if __name__ == "__main__":
    raise SystemExit(main())
