---
title: Python 3.14 and platform qualification follow-up
---

# Python 3.14 and platform qualification follow-up

Evidence collected on 2026-09-29 for [#101](https://github.com/stef-k/Offenders/issues/101).
Base: `ea8825c7ee3d9e8dd16a993bbeac0f154c610a04`, including merged #100.
The runtime and tests under qualification are commit
`fcb07d5f5936ef5b6fcf51c7616410ff9fc1b13b` (package version 0.2.1, with unreleased Export and Help).
Subsequent changes in this PR are qualification documentation and changelog only.
[The #98 record](qualification-98.md) remains the prior investigation evidence.

## Support decisions

| Platform | Decision | Evidence boundary |
| --- | --- | --- |
| Ubuntu 24.04 LTS | Established baseline retained | Python 3.12 suite passes |
| Ubuntu 26.04 LTS | **not yet claimed** | Default-stack container checks below; successful booted systemd/Fail2Ban integration still missing |
| Debian 13 | **not yet claimed** | #98 container evidence retained; no booted test host available |

The operator confirmed that no test host is available and authorized disposable
Docker qualification. Local inspection found no `/dev/kvm`, QEMU, virsh, or
Multipass. Docker containers share the host kernel and do not establish the
booted-host evidence required by this issue. Debian's missing evidence is not an
observed incompatibility; its broad #98 container investigation was not repeated.
The Python 3.13 run below checks the changed parser across runtimes, not Debian
host integration. README, Installation, and package support metadata retain only
the established baseline. Neither dependency floor changes.

## Generic timestamp correction

The existing timestamp regex now owns hour `00..23`, minute `00..59`, and second
`00..59` ranges. `datetime.fromisoformat()` still validates calendar dates and
constructs naive local-wall-clock timestamps. The existing fractional grammar
(one through six digits, comma or dot) and report window behavior are unchanged.
No distro or interpreter branch was introduced.

On the Ubuntu container's Python 3.14.4, the original parser demonstrably turns
`2026-09-27 24:00:00 [sshd] Ban 8.8.8.8` into a September 28 event. The corrected
parser rejects it. The existing malformed-record regression remains intact.
New focused cases cover midnight, `23:59:59`, fractional endpoints, `24:00:00`
with/without a fraction, minute/second overflow, negative components, impossible
hours, wrong field width, excess fractional precision, invalid dates and leap day.

## Reproduction and evidence classification

Ubuntu uses `ubuntu:26.04` on linux/amd64, manifest digest
`sha256:da6fc2be547864451aa253836dd926da33623312df4a9a243e35dc877c378a78`.
A clean container installs `python3 python3-venv pipx fail2ban sudo iproute2
systemd ca-certificates` from its normal apt sources. It does not start or
configure Fail2Ban, grant sudo rights, or issue ban/unban commands.

Extract `git archive fcb07d5` into `/work`, owned by disposable user `qualifier`.
As that ordinary user:

```sh
cd /work
python3 -m venv ~/build
~/build/bin/python -m pip install build twine
~/build/bin/python -m build
~/build/bin/python -m twine check --strict dist/*
~/build/bin/python scripts/check_distribution.py
pipx ensurepath
pipx install /work/dist/*.whl
pipx runpip offenders check
~/.local/share/pipx/venvs/offenders/bin/python -m unittest discover -s tests -v
```

Use a tests-only directory outside `/work` for the installed-wheel
`test_runtime.py` startup/Help smoke, not for the whole ordinary suite: the latter
includes a source-layout audit. For the focused run, use unittest discovery with
`-p test_parsing.py`. pipx reinstall/uninstall and external service probes run
separately. The local wheel substitutes the unreleased candidate for the public
index package; no publication or public-index candidate installation is claimed.

## Runtime and package results

| Check | Result |
| --- | --- |
| Baseline Python 3.12.3 | 157 tests pass; one optional real-regex skip (Fail2Ban regex tool absent locally) |
| Python 3.13.15 | 157 tests pass; same optional skip; disposable uv environment with prebuilt CPython, not a distro installation path |
| Ubuntu Python 3.14.4 | 157 tests pass, no skips, including installed `fail2ban-regex` |
| Focused parser suite | Six tests pass on each of Python 3.12, 3.13 and 3.14 |
| Ubuntu package build | Wheel and sdist build; strict Twine and `scripts/check_distribution.py` pass |
| Installed wheel | Two runtime tests pass outside checkout, including startup, dashboard navigation, and Help |
| Dependency integrity | pipx `pip check` passes |

Ubuntu reports 26.04.1 LTS; packages are Python `3.14.3-0ubuntu2` (interpreter
3.14.4), Fail2Ban `1.1.0-9`, pipx `1.8.0-1`, systemd `259.5-0ubuntu3.4`.
Resolved runtime dependencies include Textual 8.2.8, maxminddb 3.2.0,
dnspython 2.8.0 and ipwhois 1.3.0. This is default-stack evidence, without PPAs,
source-built interpreters, alternate Fail2Ban sources, or a new CI matrix.

## Ubuntu integration evidence and limits

- **Parser/acquisition:** ordinary tests exercise actual plain/rotated/gzip log
  fixtures, timestamp rejection, period boundaries and report assembly. Live
  successful daemon-backed report acquisition is still unverified.
- **Fail2Ban:** `/usr/bin/fail2ban-client` reports 1.1.0. Six synthetic responses
  from the distro's own `Beautifier` produce correctly parsed global/jail status,
  populated/empty logpath and populated/empty journalmatch. This proves formatter
  compatibility, not live jail/settings queries. Real status reports an absent
  daemon socket; `sudo -n` is denied without prompting.
- **Coverage:** actual `ss -H -lntu` succeeds. Installed-package host discovery,
  source discovery and Coverage run without crashing. Process ownership is
  unavailable under denied sudo, and the actual `systemctl show` path reports
  missing systemd/bus. Static configuration remains discoverable. An empty journal
  query does not establish successful journal-backed service discovery. Permission
  denial is retained as unavailable evidence, not authoritative empty state.
- **Registration/RDNS:** real ordinary-user requests for `8.8.8.8` return successful
  RDAP registration and PTR `dns.google`. Tests cover failure states; live success
  is only a point-in-time network observation.
- **Export:** ordinary tests pass for retained committed TUI reports, headless
  one-snapshot dispatch, CSV contents, private atomic publication and failures.
  Those success cases use fixtures/mocks at acquisition boundaries. The actual
  installed headless command fails cleanly with unreadable `/var/log/fail2ban.log`
  and no traceback. A successful live TUI/headless export remains unverified.
- **Help:** both the installed-wheel runtime smoke and an unmocked degraded
  dashboard open Help and return/quit successfully; contextual screens are covered
  by the ordinary suite without initiating acquisition from Help.

- **GeoIP:** initial status creates no XDG data directory. Explicit update
  downloads and activates September 2026 Country/ASN databases; both report
  healthy. Automatic policy on/off succeeds. Ordinary tests cover failed updates,
  locking and retained generations.
- **pipx lifecycle:** local-wheel install, reinstall, dependency check, status
  and uninstall all pass as the ordinary user.

## Remaining booted-host qualification

For **each** additional platform, successful ordinary-user pipx operation on a
booted host remains required: global/jail status and relevant settings,
logpath/journalmatch, at least one successful normal report acquisition, the `ss`
and systemd paths used by Coverage, TUI Export from that committed report,
headless Export, and Help. A disposable fixture may be provisioned by the
qualification environment; Offenders must remain read-only. Debian release,
Python, Fail2Ban and systemd versions must be recorded from that actual host.
No Debian host results are inferred from Ubuntu or prior container checks.

Neither platform earns an additional support claim. This does not block v0.3.0
under the issue contract; #97 must use the existing Ubuntu 24.04 baseline.

## Delivery checks and cleanup

Code Guard passes for the complete four-file change, with no REVIEW findings;
`git diff --check` passes. No PR CI is configured: these are local/container
results, not CI or production qualification. No Fail2Ban configuration or bans
were changed. The disposable Ubuntu container (including pipx environments and
GeoIP data) and its newly pulled image were removed after qualification.
Concise evidence is retained here; raw logs remain outside the repository.
