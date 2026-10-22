---
title: Python HTTPS trust audit
---

# Python HTTPS trust audit

This records the bounded investigation for [#132](https://github.com/stef-k/Offenders/issues/132)
on 2026-10-23. The [PSF advisory](https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576)
requires pip **26.2.2** and recommends certifi **2026.10.19**. The
[certifi change](https://github.com/certifi/python-certifi/compare/2026.07.22...2026.10.19)
removes **emSign ECC Root CA - G3**; emSign G1, C1 and C3 remain in the patched
bundle. An emSign name alone does not establish affected trust.

## Installation and release downloads

The old release workflow used whatever pip `setup-python` and `venv` supplied
before downloading build tools and runtime dependencies. The inspected local
development environment had pip **26.2.1**, standalone certifi **2026.7.22**, and
emSign ECC G3 in both pip's vendored bundle and standalone certifi. This establishes
affected trust material, not a demonstrated interception or compromised artifact.

`scripts/bootstrap_pip.py` now installs the advisory's exact pip 26.2.2 wheel with
its published SHA-256 before index access, separately for the build interpreter
and the fresh wheel-smoke venv. The bootstrap disables index, dependency, cache
and pip version-check access. The digest authenticates that first download
despite the old tool's trust store. No trust bypass or unpinned self-upgrade is
used. Subsequent release dependency downloads use patched pip's vendored certifi
2026.10.19 exclusively (`PIP_USE_DEPRECATED=legacy-certs`); pip's normal merged
OS/certifi mode could otherwise reintroduce stale runner roots. Revisit that
setting when changing the pinned pip version. It is set only after each
bootstrap because old ensurepip versions reject the option. There is no ordinary
PR CI workflow.

The separate publish job still consumes only the built artifacts and uses OIDC
Trusted Publishing. The inspected upstream `pypa/gh-action-pypi-publish@release/v1`
constraints already specify certifi **2026.10.19** and sigstore **4.5.1**; no
local publish tooling or upload token is introduced. Its container is maintained
upstream, so source constraints alone do not prove the contents of a cached image;
the eventual release job is separate evidence. Upstream Docker build prerequisites
still pin pip **26.2**, whose embedded bundle is affected. That pip is used when
upstream builds its image; the inspected publish entrypoint performs no pip or
dependency installation. Uploads, OIDC and attestations use the patched runtime
Requests/certifi and sigstore dependencies above. This is a retained upstream
image-build provenance limit, not a demonstrated Offenders upload exploit.

The [installation guide](installation.md#secure-pipx-bootstrap) applies the same
hash-pinned bootstrap to pipx's shared pip before app installation or upgrade.
Ubuntu OS certificate updates are a separate prerequisite. A 0.4.1 patch release
publishes the corrected installation contract in the README/PyPI description;
it does **not** update pip or the OS trust store in an existing installation.

## Runtime trust

| Path | Actual transport and authority |
| --- | --- |
| GeoIP database update | `urllib.request` HTTPSHandler → Python `ssl` default context → OS CA file/directory; fixed HTTPS provider, redirects refused |
| Registration | ipwhois **1.3.0** Net opener → `urllib.request` HTTPSHandler → the same default OS context; HTTPS ARIN bootstrap and registry redirects, zero retries |
| RDNS | dnspython resolver using host DNS configuration; no HTTPS/certifi path |
| Local GeoIP reads, dashboard and export | Local files/host commands; no TLS acquisition |

Neither Offenders nor its runtime dependencies vendor a CA bundle or import
certifi for these paths. The wheel contains application modules and metadata,
not pip, certifi, a Python interpreter or an OS image. No runtime dependency
upgrade or alternate runtime CA authority is needed for the observed environment.
Provider or transport failures retain the existing unavailable/error outcomes.

The inspected host is **Ubuntu 24.04.5**, Python **3.12.3**, OpenSSL **3.0.13**,
`ca-certificates` **20260816ubuntu0.24.04.1**. Python resolves its defaults to
`/usr/lib/ssl/cert.pem` and `/usr/lib/ssl/certs` (Ubuntu's `/etc/ssl` store).
`/etc/ca-certificates.conf` disables `mozilla/emSign_ECC_Root_CA_-_G3.crt`;
the loaded default CA file and installed CA directory contain no active G3 root.
`SSL_CERT_FILE` and `SSL_CERT_DIR` can change that authority on other hosts.
Old or custom OS stores remain the operator's responsibility; this is not a
claim that every existing Offenders host has updated trust.

## Validation boundary

Offline tests exercise the real GeoIP and ipwhois HTTPS paths at the connection
boundary, checking hostname/certificate verification, OS-root ownership and
certificate-error propagation without DNS/provider requests. Existing tests cover
HTTP failures, offline operation, GeoIP preservation and CLI outcomes. Release
qualification also checks wheel/sdist identity and contents, installed-wheel
startup and read-only status, and disposable pipx installation mechanics.
No hostile chain, interception, production host or Fail2Ban enforcement was tested.
