# Distribution and release

Offenders uses setuptools, a standard wheel and sdist, and pipx for Linux users.
`pyproject.toml` owns the name, version, Python floor, and runtime dependencies.
The command stays `offenders`; pipx is not an application dependency. Host tools
and XDG GeoIP data remain outside the distributions.

## Identity and first release gate

The preferred normalized PyPI name is `offenders`. On 2026-09-28,
`https://pypi.org/pypi/offenders/json` returned HTTP 404 (`Not Found`). This is an
authoritative index check for an existing public project, **not a reservation or
proof that registration will succeed**. Recheck immediately before first
publication. PyPI normalizes runs of `-`, `_`, and `.` to `-` and ignores case.

If PyPI rejects `offenders` as owned, reserved, prohibited, or too-confusable,
record the response and check the approved fallback `fail2ban-offenders` using
its normalized PyPI identity. Only then change `[project].name` and the pipx
install/upgrade/uninstall instructions; keep the executable `offenders`. If both
names are unavailable, stop for a maintainer decision. Never upload just to test
availability. A pending publisher does not reserve a name.

The first final tag/release must wait for final repository documentation and
release qualification. Publishing a release is an explicit maintainer action.
Production deployment qualification, live installation, and legacy-command cutover
with rollback are a separate post-release gate. No packaging check
qualifies production or downloads the production GeoIP data.

## Local qualification

Use a clean checkout of the intended commit on Ubuntu 24.04 / Python 3.12.
Record `git rev-parse HEAD` and confirm `git status --porcelain` is empty before
building. Use an isolated development environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e . build twine
python -m unittest discover -s tests -v
python -m build
python -m twine check --strict dist/*
python scripts/check_distribution.py
```

`dist/` must contain exactly the intended wheel and sdist. The checker compares
metadata, dependencies, entrypoint, README, LICENSE, runtime modules, and allowed
contents with the source contract. Run without Python's `-O` flag (checks use
assertions). The build frontend builds the wheel through the sdist by default.
The release workflow also installs the wheel into a fresh venv outside the
checkout and reuses the existing offline dashboard runtime tests there.

For pipx validation, use disposable directories and absolute wheel paths:

```bash
wheel=$(realpath dist/*.whl)
scratch=$(mktemp -d)
export PIPX_HOME="$scratch/pipx" PIPX_BIN_DIR="$scratch/bin"
export PIPX_MAN_DIR="$scratch/man" XDG_DATA_HOME="$scratch/data"
pipx install "$wheel"
cd "$scratch"
"$PIPX_BIN_DIR/offenders" geoip status
test ! -e "$XDG_DATA_HOME"
pipx reinstall offenders
"$PIPX_BIN_DIR/offenders" geoip status
pipx uninstall offenders
```

Reinstall exercises replacement from the recorded local wheel; normal published
updates use `pipx upgrade offenders`. These temporary paths avoid the operator's
existing pipx applications and GeoIP policy. Retain evidence as needed, then
remove only the disposable directory you created. Source/editable contributor workflows
are described in [DEVELOPMENT.md](DEVELOPMENT.md). No PyPI upload is needed for local qualification.

## Trusted Publishing setup

Before publication through `.github/workflows/release.yml`, the maintainer must:

1. Create the GitHub environment `pypi`, requiring explicit maintainer approval
   where the repository plan supports it. Restrict allowed deployment tags as
   appropriate for releases.
2. Configure the PyPI Trusted Publisher with owner `stef-k`, repository
   `Offenders`, workflow filename `release.yml`, and environment `pypi`.
   For an absent project, use PyPI's pending-publisher flow with the selected name.
3. After final documentation and release qualification, recheck name availability,
   set the single project version through review, and create `v<project.version>` at the qualified commit. Deliberately
   publish its GitHub Release and approve the environment job.

See PyPI's [publisher setup](https://docs.pypi.org/trusted-publishers/adding-a-publisher/)
and [pending-publisher documentation](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/).
Do not configure a long-lived PyPI username/password/API-token secret.

The release-published event is the only trigger. The read-only build job checks
out the exact release tag, rejects a version mismatch before building, validates
both distributions, and transfers only those files. The separate `pypi` job has
`id-token: write`, no checkout/build, and uses PyPA's standard publishing action.
There is no PR, branch-push, or manual untagged publication route.

Static workflow review and local artifact validation do not prove OIDC exchange.
That evidence requires the registered publisher and a deliberate real release.
Do not republish or create a test release to close this evidence gap.
