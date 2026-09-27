"""Explicit, bounded DB-IP acquisition and atomic rootless pair activation."""
from __future__ import annotations

from contextlib import contextmanager
import datetime as dt
import gzip
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import time
import urllib.error
import urllib.request
import uuid

from offenders_geoip import resolve_data_root, validate_database

BASE_URL = "https://download.db-ip.com/free"
TIMEOUT = 30  # Seconds for connection and each blocking socket read.
MAX_COMPRESSED = 128 * 1024 * 1024
MAX_DECOMPRESSED = 512 * 1024 * 1024
CHUNK = 64 * 1024
KINDS = ("country", "asn")


class UpdateError(Exception):
    """An expected acquisition, validation, or writer coordination failure."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Fail closed on redirects, including HTTPS-to-HTTP downgrades."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise UpdateError("Download redirects are not allowed")


def fetch(url):
    """Open only the fixed HTTPS provider with bounded socket operations."""
    if not url.startswith(BASE_URL + "/"):
        raise UpdateError("Unsupported download source")
    request = urllib.request.Request(url, headers={"User-Agent": "Offenders/0.1 GeoIP updater"})
    return urllib.request.build_opener(_NoRedirect()).open(request, timeout=TIMEOUT)


@contextmanager
def writer_lock(root):
    """Serialize policy and updates; refuse unsupported or concurrent writers."""
    try:
        import fcntl
    except ImportError as error:
        raise UpdateError("GeoIP writer locking is unavailable") from error
    root.mkdir(parents=True, exist_ok=True)
    with (root / "writer.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise UpdateError("GeoIP writer lock unavailable or update already running") from error
        yield


def read_state(root):
    """Read policy without side effects; malformed state fails closed."""
    try:
        state = json.loads((root / "state.json").read_text())
        if not isinstance(state, dict):
            raise ValueError("Expected an object")
        return state
    except FileNotFoundError:
        return {}
    except (ValueError, OSError) as error:
        raise UpdateError(f"Cannot read GeoIP state: {error}") from error


def _write_state(root, state):
    """Replace policy/check state atomically under the writer lock."""
    temporary = root / "state.tmp"
    try:
        temporary.write_text(json.dumps(state) + "\n")
        os.replace(temporary, root / "state.json")
    finally:
        temporary.unlink(missing_ok=True)


def set_auto(enabled, root=None):
    """Persist explicit opt-in without triggering a network check."""
    root = root if root is not None else resolve_data_root()
    with writer_lock(root):
        state = read_state(root)
        state["auto"] = bool(enabled)
        _write_state(root, state)


def automatic_due(state, now=None):
    """Expose the opt-in/24-hour policy for a future caller, without scheduling."""
    if state.get("auto") is not True:
        return False
    last = state.get("last_check")
    return last is None or (isinstance(last, (int, float)) and
                            (time.time() if now is None else now) - last >= 86400)


def _copy_bounded(source, target, limit):
    """Stream with a strict size bound and return the actual byte count."""
    total = 0
    while chunk := source.read(CHUNK):
        total += len(chunk)
        if total > limit:
            raise UpdateError(f"Database exceeds {limit} byte limit")
        target.write(chunk)
    return total


def _download_pair(stage, month, opener):
    """Download one candidate month; only a 404 permits publication fallback."""
    for kind in KINDS:
        url = f"{BASE_URL}/dbip-{kind}-lite-{month}.mmdb.gz"
        archive = stage / "download.gz"
        with opener(url) as response, archive.open("wb") as target:
            if not 200 <= response.status < 300:
                raise urllib.error.HTTPError(url, response.status, "Download failed", {}, None)
            size = _copy_bounded(response, target, MAX_COMPRESSED)
            expected = response.headers.get("Content-Length")
            if expected is not None and size != int(expected):
                raise UpdateError("Truncated download (Content-Length mismatch)")
        path = stage / f"dbip-{kind}-lite.mmdb"
        with gzip.open(archive, "rb") as source, path.open("wb") as target:
            _copy_bounded(source, target, MAX_DECOMPRESSED)
        archive.unlink()
        validate_database(path, kind)


def _prune(root, active, previous):
    """Remove only engine-owned complete generations, preserving the old active."""
    complete = []
    for path in (root / "generations").iterdir():
        if path.is_symlink() or not re.fullmatch(r"\d{4}-\d{2}-[0-9a-f]{32}", path.name):
            continue
        if all((path / f"dbip-{kind}-lite.mmdb").is_file() for kind in KINDS):
            complete.append(path)
    keep = {active, previous}
    if previous not in complete:
        older = sorted((p for p in complete if p != active), key=lambda p: p.stat().st_mtime_ns)
        keep.update(older[-1:])
    for path in complete:
        if path not in keep:
            shutil.rmtree(path)


def _activate(root, stage, month):
    """Finalize immutable data then atomically replace the pair reference."""
    generations = root / "generations"
    generations.mkdir(exist_ok=True)
    destination = generations / f"{month}-{uuid.uuid4().hex}"
    current = root / "current"
    previous = current.resolve() if current.is_symlink() else None
    link = root / "current.tmp"
    os.replace(stage, destination)
    try:
        link.symlink_to(destination.relative_to(root))
        os.replace(link, current)
    except Exception:
        shutil.rmtree(destination)
        raise
    finally:
        link.unlink(missing_ok=True)
    return destination, previous


def update(root=None, *, opener=fetch, now=None, automatic=False):
    """Update explicitly, or atomically claim a due automatic check for #18."""
    root = (root if root is not None else resolve_data_root()).absolute()
    now = time.time() if now is None else now
    with writer_lock(root):
        state = read_state(root)
        if automatic and not automatic_due(state, now):
            return None
        state.update(last_check=now, outcome="checking")
        _write_state(root, state)
        try:
            month = dt.datetime.fromtimestamp(now, dt.timezone.utc).date().replace(day=1)
            with tempfile.TemporaryDirectory(prefix=".staging-", dir=root) as temporary:
                stage = Path(temporary) / "pair"
                stage.mkdir()
                try:
                    _download_pair(stage, month.strftime("%Y-%m"), opener)
                except urllib.error.HTTPError as error:
                    if error.code != 404:
                        raise
                    month -= dt.timedelta(days=1)
                    _download_pair(stage, month.strftime("%Y-%m"), opener)
                label = month.strftime("%Y-%m")
                active, previous = _activate(root, stage, label)
        except Exception as error:
            state["outcome"] = f"failed: {str(error)[:240]}"
            try:
                _write_state(root, state)
            except OSError:
                pass  # Preserve the primary acquisition failure.
            raise UpdateError(state["outcome"]) from error
        # Activation is committed: housekeeping failures must not claim rollback.
        state.update(outcome="updated", generation=label)
        try:
            _write_state(root, state)
            _prune(root, active, previous)
        except OSError as error:
            return f"{label} (activated; housekeeping failed: {error})"
        return label
