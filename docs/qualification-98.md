---
title: Phase A platform qualification
---

# Phase A platform qualification

Evidence collected on 2026-09-29 for [issue #98](https://github.com/stef-k/Offenders/issues/98),
against master `126ddd961f301307faab3737649a4c7efb359262` (package version 0.2.1,
including unreleased Export and Help). This is a bounded pre-v0.3 investigation,
not a broader compatibility implementation. Python >=3.12 and Fail2Ban >=1.0.2
remain unchanged. No production code, dependency bounds, classifiers, or CI jobs
change: no additional platform earned a support claim.

## Support decision

| Platform | Decision | Evidence / remaining gate |
| --- | --- | --- |
| Ubuntu 24.04 LTS | Existing known-good baseline | Python 3.12 local suite: 156 tests, OK, one optional real-regex skip |
| Ubuntu 26.04 LTS | **Not yet claimed** | Python 3.14.4 exposes the existing timestamp rejection contract failure below; defer compatibility work |
| Debian 13 | **Not yet claimed** | All 156 tests pass; successful live Fail2Ban and systemd integration unavailable |
| Ubuntu 22.04 LTS | **Unsupported under current contract** | Default Python 3.10.12 and Fail2Ban 0.11.2 miss both floors; no qualified alternate stack |

The Debian result is an **evidence gap, not an observed incompatibility**. It does
not satisfy the issue's successful host-integration acceptance gate. No running
26.04/Debian 13 test hosts were available; the operator confirmed only the current
WSL environment. Do not promote a container test pass to full distro support.
These results do not delay v0.3.0. Broader Phase B work remains deferred, and this
report does not assert that every Phase A acceptance criterion passed.

## Environments and reproducibility

Disposable Docker containers used distro-default Python and official apt sources
on linux/amd64. They share the Docker host kernel; they are not booted systemd
VMs. No host Fail2Ban configuration, daemon, or bans were changed. No daemon was
started in a container, and no mutation command or sudoers grant was added.

| Image / exact OS | Python | Fail2Ban package | pipx |
| --- | --- | --- | --- |
| `ubuntu:26.04` / Ubuntu 26.04.1 LTS | 3.14.4 | 1.1.0-9 | 1.8.0 |
| `debian:13` / Debian 13.7 (trixie) | 3.13.5 | 1.1.0-8 | 1.7.1 |
| `ubuntu:22.04` / Ubuntu 22.04.5 LTS | 3.10.12 | 0.11.2-6 | 1.0.0 |

Pulled image manifest digests:

```text
ubuntu:26.04 sha256:da6fc2be547864451aa253836dd926da33623312df4a9a243e35dc877c378a78
debian:13    sha256:9cc080028c43b27d2074d63a5f9caf7166d731494965616c1a6d2827a004585c
ubuntu:22.04 sha256:b8b6ee6aa931ecd9d0d952abc34dc0e5f7c6a30c6bb71b079fe399fde0329c02
```

For 26.04/13, install `python3 python3-venv pipx fail2ban sudo iproute2 systemd
ca-certificates` in the disposable environment. Extract `git archive` of the base
commit into `/work`, owned by an ordinary `qualifier` user. As that user:

```bash
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

The local wheel substitutes the unreleased candidate for `pipx install offenders`;
this does not qualify an unreleased package through the public index. Dependencies
resolved from PyPI: Textual 8.2.8, maxminddb 3.2.0, dnspython 2.8.0, ipwhois 1.3.0.
Both builds, strict Twine checks, distribution checks, and `pip check` passed.
The installed command was reachable in a new login shell after `ensurepath`.

## Runtime results on Ubuntu 26.04 and Debian 13

| Area | Result on both unless stated otherwise |
| --- | --- |
| Ordinary suite | 26.04: 156 tests, one parser failure; Debian: 156 tests, all pass, no skips |
| Installed wheel | Imports resolve from pipx site-packages; two `test_runtime.py` tests pass outside checkout, including dashboard and Help |
| Report parsing/acquisition | Existing file/rotation/gzip and acquisition tests exercised; 26.04 timestamp defect below; live successful acquisition unverified |
| Fail2Ban client | `/usr/bin/fail2ban-client`, version 1.1.0; six synthetic distro-formatter responses accepted by Offenders status/logpath/journalmatch parsers |
| Real regex | Existing candidate-template test passes against installed `fail2ban-regex`; no daemon/configuration/ban writes |
| Host acquisition | Real `ss` succeeds; noninteractive sudo denial and missing systemd bus become unavailable evidence without crashing |
| Coverage | Static distro configuration discovery and graceful degradation exercised; empty journal query is not proof of journal-backed service discovery |
| GeoIP | Initial status creates no XDG directory; explicit update downloads and activates September 2026 Country/ASN data, both healthy; policy on/off succeeds |
| Registration/RDNS | Real 8.8.8.8 RDAP and PTR requests return success; ordinary tests cover failure states |
| Export | TUI/headless success and atomic publication covered by existing tests; actual unprivileged CLI reports unreadable Fail2Ban log without traceback |
| Help/TUI | Unmocked degraded startup, Help open/return, and quit pass; contextual product screens covered by existing tests |
| pipx lifecycle | Local-wheel install, reinstall, status, and uninstall exercised |

GeoIP lifecycle tests additionally cover failed updates, retained generations,
locking, and automatic policy. Network success is a point-in-time observation,
not a provider availability guarantee. Real successful report/export acquisition,
live jail counters/settings/source queries, journal-backed services, and a booted
systemd host remain unverified. The container's absent daemon and permissions
must not be interpreted as distro defects or worked around in application code.

An initial attempt to run the entire suite from a copied tests-only directory
also failed the source-layout worker audit: it finds no sibling runtime modules.
The corrected ordinary runs above use `/work`; the separate installed-wheel
check uses `test_runtime.py`, matching the existing release workflow. No test was
changed or suppressed. The Ubuntu parser failure remains in the corrected run.

## Ubuntu 26.04 compatibility finding

`tests/test_parsing.py::ParsingTests.test_incomplete_or_malformed_records_are_not_events`
fails for `2026-09-27 24:00:00 [sshd] Ban 8.8.8.8`.
`offenders_events.parse_ban_event` relies on `datetime.fromisoformat` to reject
invalid clock values. Direct interpreter probes established:

```text
Python 3.14.4: datetime.fromisoformat('2026-09-27 24:00:00')
              -> datetime.datetime(2026, 9, 28, 0, 0)
Python 3.13.5: same input -> ValueError: hour must be in 0..23
```

Thus malformed history can become a real event on the next day under the tested
26.04 default runtime. This affects the report contract, not just test machinery.
Retain the existing regression test and defer explicit timestamp validation or
other compatibility changes to separately authorized work. Do not weaken the
test, change the Python floor, or claim 26.04 support to bypass this result.

## Ubuntu 22.04 feasibility

Official apt metadata and a clean install report Python 3.10.12, Fail2Ban
0.11.2-6, and pipx 1.0.0-1. `apt-cache policy python3 python3.11 python3.12
fail2ban pipx` offers Python 3.11.0~rc1-1~22.04.1 but no Python 3.12 candidate
in the configured repositories. Installing the unchanged project in a fresh
3.10 venv fails with `requires a different Python: 3.10.12 not in '>=3.12'`.
The [Ubuntu package record](https://packages.ubuntu.com/jammy/all/fail2ban)
also identifies Fail2Ban 0.11.2-6.

No simple distro-supported alternate >=3.12 stack was established. Supplying
another interpreter to pipx would still require a separately maintained Python
installation, and Fail2Ban would independently need a newer package/source
installation. PPAs, source builds, or manual system-Python replacement are not
adopted as an installation story here. Prefer the existing supported OS baseline.

Lower Python floors appear technically plausible, but are **not qualified**:
all 32 runtime modules parse under Python 3.10/3.11 grammar, and a Python 3.10
wheel-resolution dry run succeeds for the current dependency bounds. Textual
8.2.8 declares >=3.9,<4; maxminddb 3.2.0 and dnspython 2.8.0 declare >=3.10.
This does not prove runtime behavior, the whole supported dependency range, or
future resolver choices. `tomllib` is used by the distribution checker (a 3.11+
tooling dependency), not the shipped runtime. No lower-floor full suite was run.

For Fail2Ban 0.11.2, the distro's own client formatter produces accepted global
status, jail status, populated/empty logpath, and populated/empty journalmatch
outputs in six synthetic probes. Its regex help exposes the used DNS, encoding,
date-pattern, and matched-line options. No inspected assumption established a
hard 1.0.2 requirement in these limited paths; equally, this is not live daemon,
filter-catalog, or full validation qualification. Treat 0.11.2 as below the
supported floor and unqualified, not as proven concretely incompatible.

Real 22.04 support would require separate Python 3.10/3.11 runtime and dependency
qualification, older Fail2Ban command/parser/filter tests, a durable alternate
stack or reviewed floor change, and ongoing install/security documentation.
That recurring maintenance has no established Phase A benefit sufficient to
justify widening policy before v0.3.0. Neither floor is lowered.
