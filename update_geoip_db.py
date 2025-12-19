#!/usr/bin/env python3
"""
DB-IP GeoIP Database Auto-Updater (Country + ASN, free monthly MMDBs)

Behavior:
- Downloads dbip-country-lite-YYYY-MM.mmdb.gz and dbip-asn-lite-YYYY-MM.mmdb.gz
- Decompresses
- Installs into /usr/share/GeoIP
- Updates symlinks:
    dbip-country-lite.mmdb -> dbip-country-lite-YYYY-MM.mmdb
    dbip-asn-lite.mmdb     -> dbip-asn-lite-YYYY-MM.mmdb

Cron-friendly:
- Uses logging with timestamps (stderr by default)
- Optional file logging (--log-file) and syslog (--syslog)
- Optional lock file to avoid overlapping runs (--lock-file)
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import logging
import os
import shutil
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

BASE_URL = "https://download.db-ip.com/free"


@dataclass(frozen=True)
class Plan:
    month: str  # YYYY-MM
    country_gz: str
    asn_gz: str
    country_mmdb: str
    asn_mmdb: str

    @staticmethod
    def for_month(month: str) -> "Plan":
        country_gz = f"dbip-country-lite-{month}.mmdb.gz"
        asn_gz = f"dbip-asn-lite-{month}.mmdb.gz"
        return Plan(
            month=month,
            country_gz=country_gz,
            asn_gz=asn_gz,
            country_mmdb=country_gz.removesuffix(".gz"),
            asn_mmdb=asn_gz.removesuffix(".gz"),
        )


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def human_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    f = float(n)
    for u in units:
        if f < 1024.0 or u == units[-1]:
            return f"{f:.1f} {u}" if u != "B" else f"{int(f)} {u}"
        f /= 1024.0
    return f"{n} B"


def month_now_local() -> str:
    return dt.datetime.now().strftime("%Y-%m")


def month_prev(month_yyyy_mm: str) -> str:
    y, m = month_yyyy_mm.split("-")
    y_i = int(y)
    m_i = int(m)
    if m_i == 1:
        return f"{y_i - 1:04d}-12"
    return f"{y_i:04d}-{m_i - 1:02d}"


def require_writable_target(target_dir: Path, logger: logging.Logger) -> None:
    # If directory doesn't exist, parent must be writable
    if target_dir.exists():
        if os.access(target_dir, os.W_OK):
            return
    else:
        parent = target_dir.parent
        if parent.exists() and os.access(parent, os.W_OK):
            return

    msg = f"Target directory is not writable: {target_dir}"
    if not is_root():
        msg += " (run as root, e.g. from root crontab or via sudo)"
    logger.error(msg)
    raise PermissionError(msg)


def head_request_ok(url: str, timeout: int) -> bool:
    req = urllib.request.Request(url, method="HEAD")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except urllib.error.HTTPError as ex:
        if ex.code == 404:
            return False
        raise


def download(url: str, dest: Path, timeout: int) -> int:
    req = urllib.request.Request(url, headers={"User-Agent": "dbip-geoip-updater/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        ensure_dir(dest.parent)
        written = 0
        with open(dest, "wb") as f:
            while True:
                chunk = resp.read(1024 * 256)
                if not chunk:
                    break
                f.write(chunk)
                written += len(chunk)
    return written


def gunzip_to(src_gz: Path, dest: Path) -> int:
    if not src_gz.exists():
        raise FileNotFoundError(f"Missing gzip file: {src_gz}")

    written = 0
    with gzip.open(src_gz, "rb") as fin, open(dest, "wb") as fout:
        while True:
            chunk = fin.read(1024 * 256)
            if not chunk:
                break
            fout.write(chunk)
            written += len(chunk)
    return written


def atomic_replace(src: Path, dest: Path) -> None:
    """
    Atomically replace dest with src (same filesystem required).
    We stage into dest.parent then os.replace.
    """
    ensure_dir(dest.parent)
    tmp_dest = dest.with_name(dest.name + ".tmp")
    if tmp_dest.exists():
        tmp_dest.unlink()
    shutil.move(str(src), str(tmp_dest))
    os.replace(tmp_dest, dest)


def atomic_symlink(target_name: str, link_path: Path) -> None:
    """
    Atomically replace a symlink by creating link_path.tmp then os.replace.
    Uses a relative symlink (target_name only).
    """
    tmp_link = link_path.with_name(link_path.name + ".tmp")
    try:
        if tmp_link.exists() or tmp_link.is_symlink():
            tmp_link.unlink()
        tmp_link.symlink_to(target_name)
        os.replace(tmp_link, link_path)
    finally:
        # If replace failed, tmp may still exist
        if tmp_link.exists() and tmp_link.is_symlink():
            try:
                tmp_link.unlink()
            except OSError:
                pass


def acquire_lock(lock_file: Path, logger: logging.Logger):
    """
    Best-effort lock (POSIX). If lock cannot be acquired, return None.
    If fcntl isn't available (non-POSIX), we skip locking.
    """
    try:
        import fcntl  # type: ignore
    except Exception:
        logger.info("Locking not available on this platform; continuing without lock.")
        return None

    ensure_dir(lock_file.parent)
    fd = os.open(lock_file, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.ftruncate(fd, 0)
        os.write(fd, str(os.getpid()).encode("ascii", "replace"))
        return fd
    except BlockingIOError:
        logger.warning(
            "Another instance is already running (lock: %s). Exiting.", lock_file
        )
        os.close(fd)
        return None


def release_lock(fd, logger: logging.Logger) -> None:
    if fd is None:
        return
    try:
        import fcntl  # type: ignore

        fcntl.flock(fd, fcntl.LOCK_UN)
    except Exception:
        pass
    try:
        os.close(fd)
    except OSError as ex:
        logger.debug("Failed closing lock fd: %s", ex)


def pick_plan(
    month: str, timeout: int, auto_fallback: bool, logger: logging.Logger
) -> Plan:
    primary = Plan.for_month(month)
    if not auto_fallback:
        return primary

    c_url = f"{BASE_URL}/{primary.country_gz}"
    a_url = f"{BASE_URL}/{primary.asn_gz}"

    try:
        c_ok = head_request_ok(c_url, timeout=timeout)
        a_ok = head_request_ok(a_url, timeout=timeout)
        if c_ok and a_ok:
            return primary

        prev = month_prev(month)
        logger.info("Current month files not available yet; falling back to %s", prev)
        return Plan.for_month(prev)
    except Exception as ex:
        # If HEAD is blocked/fails, try primary downloads anyway.
        logger.debug("HEAD check failed (%s). Proceeding with primary month.", ex)
        return primary


def run(
    plan: Plan, target_dir: Path, timeout: int, keep_tmp: bool, logger: logging.Logger
) -> int:
    logger.info("Starting DB-IP GeoIP update for month %s", plan.month)

    require_writable_target(target_dir, logger)

    with tempfile.TemporaryDirectory(prefix="dbip-update-") as tmp:
        tmp_dir = Path(tmp)
        logger.debug("Temp dir: %s", tmp_dir)

        country_url = f"{BASE_URL}/{plan.country_gz}"
        asn_url = f"{BASE_URL}/{plan.asn_gz}"

        country_gz_path = tmp_dir / plan.country_gz
        asn_gz_path = tmp_dir / plan.asn_gz

        try:
            logger.info("Downloading: %s", country_url)
            c_bytes = download(country_url, country_gz_path, timeout=timeout)
            logger.info(
                "Downloaded %s (%s)", country_gz_path.name, human_bytes(c_bytes)
            )

            logger.info("Downloading: %s", asn_url)
            a_bytes = download(asn_url, asn_gz_path, timeout=timeout)
            logger.info("Downloaded %s (%s)", asn_gz_path.name, human_bytes(a_bytes))
        except urllib.error.HTTPError as ex:
            logger.error("HTTP error while downloading: %s", ex)
            return 2
        except urllib.error.URLError as ex:
            logger.error("Network error while downloading: %s", ex)
            return 3

        # Basic sanity
        if country_gz_path.stat().st_size < 1024:
            logger.error(
                "Download looks too small: %s (%d bytes)",
                country_gz_path,
                country_gz_path.stat().st_size,
            )
            return 4
        if asn_gz_path.stat().st_size < 1024:
            logger.error(
                "Download looks too small: %s (%d bytes)",
                asn_gz_path,
                asn_gz_path.stat().st_size,
            )
            return 4

        country_mmdb_tmp = tmp_dir / plan.country_mmdb
        asn_mmdb_tmp = tmp_dir / plan.asn_mmdb

        try:
            logger.info("Decompressing: %s", country_gz_path.name)
            c_um = gunzip_to(country_gz_path, country_mmdb_tmp)
            logger.info(
                "Decompressed to %s (%s)", country_mmdb_tmp.name, human_bytes(c_um)
            )

            logger.info("Decompressing: %s", asn_gz_path.name)
            a_um = gunzip_to(asn_gz_path, asn_mmdb_tmp)
            logger.info("Decompressed to %s (%s)", asn_mmdb_tmp.name, human_bytes(a_um))
        except OSError as ex:
            logger.error("Decompression failed: %s", ex)
            return 5

        # MMDBs are usually multiple MB
        if country_mmdb_tmp.stat().st_size < 1024 * 1024:
            logger.error(
                "Country MMDB looks unusually small: %s",
                human_bytes(country_mmdb_tmp.stat().st_size),
            )
            return 6
        if asn_mmdb_tmp.stat().st_size < 1024 * 1024:
            logger.error(
                "ASN MMDB looks unusually small: %s",
                human_bytes(asn_mmdb_tmp.stat().st_size),
            )
            return 6

        ensure_dir(target_dir)
        country_dst = target_dir / country_mmdb_tmp.name
        asn_dst = target_dir / asn_mmdb_tmp.name

        try:
            logger.info("Installing into: %s", target_dir)
            atomic_replace(country_mmdb_tmp, country_dst)
            atomic_replace(asn_mmdb_tmp, asn_dst)
            logger.info("Installed: %s", country_dst.name)
            logger.info("Installed: %s", asn_dst.name)
        except OSError as ex:
            logger.error("Install failed: %s", ex)
            return 7

        # Update "latest" symlinks
        country_link = target_dir / "dbip-country-lite.mmdb"
        asn_link = target_dir / "dbip-asn-lite.mmdb"

        try:
            atomic_symlink(country_dst.name, country_link)
            atomic_symlink(asn_dst.name, asn_link)
            logger.info(
                "Updated symlink: %s -> %s", country_link.name, country_dst.name
            )
            logger.info("Updated symlink: %s -> %s", asn_link.name, asn_dst.name)
        except OSError as ex:
            logger.error("Symlink update failed: %s", ex)
            return 8

        if keep_tmp:
            debug_dir = Path("/tmp") / f"dbip-update-keep-{plan.month}"
            ensure_dir(debug_dir)
            try:
                shutil.copy2(country_gz_path, debug_dir / country_gz_path.name)
                shutil.copy2(asn_gz_path, debug_dir / asn_gz_path.name)
                logger.info("Kept debug copies in: %s", debug_dir)
            except OSError as ex:
                logger.warning("Failed keeping debug copies: %s", ex)

    logger.info("DB-IP databases updated successfully.")
    return 0


def setup_logging(
    log_file: str | None, use_syslog: bool, verbose: bool
) -> logging.Logger:
    logger = logging.getLogger("dbip_geoip_updater")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    # Default handler: stderr (cron will capture if you redirect)
    sh = logging.StreamHandler(stream=sys.stderr)
    sh.setLevel(logging.DEBUG if verbose else logging.INFO)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.DEBUG if verbose else logging.INFO)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    if use_syslog:
        try:
            from logging.handlers import SysLogHandler

            # Common on Ubuntu: /dev/log
            syslog_paths = ["/dev/log", "/var/run/syslog"]
            handler = None
            for p in syslog_paths:
                if Path(p).exists():
                    handler = SysLogHandler(address=p)
                    break
            if handler is None:
                # UDP fallback
                handler = SysLogHandler(address=("localhost", 514))

            handler.setLevel(logging.DEBUG if verbose else logging.INFO)
            handler.setFormatter(
                logging.Formatter("dbip-geoip-updater: %(levelname)s %(message)s")
            )
            logger.addHandler(handler)
        except Exception as ex:
            logger.warning(
                "Syslog logging requested but could not be configured: %s", ex
            )

    return logger


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Update DB-IP free GeoIP MMDBs (country + ASN)."
    )
    p.add_argument(
        "--target-dir",
        default="/usr/share/GeoIP",
        help="Where to install MMDBs (default: /usr/share/GeoIP)",
    )
    p.add_argument(
        "--month", default=None, help="Force month YYYY-MM (default: current month)"
    )
    p.add_argument(
        "--timeout", type=int, default=60, help="Network timeout seconds (default: 60)"
    )
    p.add_argument(
        "--no-fallback",
        action="store_true",
        help="Disable auto fallback to previous month on 404",
    )
    p.add_argument(
        "--keep-tmp", action="store_true", help="Keep debug copies of downloads in /tmp"
    )

    p.add_argument(
        "--log-file",
        default=None,
        help="Append logs to this file (recommended for cron)",
    )
    p.add_argument("--syslog", action="store_true", help="Also log to syslog")
    p.add_argument("--verbose", action="store_true", help="Verbose logging (debug)")

    p.add_argument(
        "--lock-file",
        default="/var/lock/dbip-geoip-update.lock",
        help="Lock file to prevent overlapping runs (default: /var/lock/dbip-geoip-update.lock)",
    )
    p.add_argument("--no-lock", action="store_true", help="Disable locking")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    logger = setup_logging(args.log_file, args.syslog, args.verbose)

    lock_fd = None
    if not args.no_lock:
        lock_fd = acquire_lock(Path(args.lock_file), logger)
        if lock_fd is None:
            # Another instance running
            return 0

    try:
        month = args.month or month_now_local()
        target_dir = Path(args.target_dir)

        plan = pick_plan(
            month,
            timeout=args.timeout,
            auto_fallback=not args.no_fallback,
            logger=logger,
        )
        return run(
            plan,
            target_dir=target_dir,
            timeout=args.timeout,
            keep_tmp=args.keep_tmp,
            logger=logger,
        )
    except PermissionError:
        return 10
    except Exception as ex:
        logger.exception("Unhandled error: %s", ex)
        return 99
    finally:
        release_lock(lock_fd, logger)


if __name__ == "__main__":
    raise SystemExit(main())
