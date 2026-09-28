---
title: Installation and permissions
---

# Installation and permissions

## Requirements and permissions

The supported baseline is **Ubuntu 24.04 LTS / Python 3.12+**, with separately
installed **Fail2Ban >=1.0.2**. pipx installs Python dependencies automatically.

The dashboard needs Fail2Ban file logs and permission to read them. Defaults are
`/var/log/fail2ban.log`, its `.1` rotation, and `.N.gz` rotations. Journal-only
Fail2Ban logging does not supply the ordinary report history.

Live jail/status/settings calls use **`sudo -n fail2ban-client`**, with an
eight-second limit per call. Offenders never waits for a sudo password. Denied
commands are failures, not authoritative zero counts. Run the dashboard as your
normal user with the required log access and narrowly scoped sudo permission.

An administrator can use `visudo` to permit only the read commands below. Replace
`OPERATOR` with the login name and verify the installed executable path with
`command -v fail2ban-client` before adapting this example. Replace `JAIL` with
an actual jail name and repeat jail-specific entries for each monitored jail:

```sudoers
OPERATOR ALL=(root) NOPASSWD: /usr/bin/fail2ban-client status, /usr/bin/fail2ban-client status JAIL, /usr/bin/fail2ban-client get JAIL bantime, /usr/bin/fail2ban-client get JAIL findtime, /usr/bin/fail2ban-client get JAIL maxretry, /usr/bin/fail2ban-client get JAIL logpath, /usr/bin/fail2ban-client get JAIL journalmatch
```

The status and first three `get` forms serve the dashboard; `logpath` and
`journalmatch` serve optional Coverage. Keep jail arguments explicit rather than
granting wildcard command access. Do not grant unrestricted
passwordless `fail2ban-client` access: it also exposes mutation commands.

Coverage can degrade independently of the ordinary dashboard:

| Evidence/action | Command or access | If unavailable |
| --- | --- | --- |
| Listener discovery | Non-sudo `ss -H -lntu` | Exposure evidence unavailable |
| Optional process owners | Bounded `sudo -n ss -H -lntup` | Owner evidence partial/unavailable |
| Systemd/source discovery | Non-sudo `systemctl` / `journalctl` | Service/journal evidence partial/unavailable |
| Static configuration | Read `/etc/fail2ban` as the current user | Coverage cannot imply complete configuration access |
| Source log evidence | Read discovered logs as the current user | Source evidence partial/unavailable |
| Explicit filter validation | Installed `fail2ban-regex`, without sudo | Validation unavailable |

Owner enrichment is optional; it does not require broad sudo permission. If an
administrator chooses to allow it, limit permission to the exact `ss` invocation
above and verify that executable's path separately.

Registration (RDAP) and RDNS (PTR) use required Python dependencies supplied by
pipx: classic `ipwhois` and `dnspython`. No separate lookup executables are needed.
RDNS uses the host DNS resolver configuration; Registration needs outbound RDAP
HTTP access. Network failures appear per request and do not disable the actions.

## Install and upgrade

Install from [PyPI](https://pypi.org/project/offenders/) using pipx:

```bash
sudo apt-get update
sudo apt-get install -y pipx
pipx ensurepath
# Open a new login shell after ensurepath, then:
pipx install offenders
command -v offenders
offenders
```

Upgrade or remove the package with:

```bash
pipx upgrade offenders
pipx uninstall offenders
```

pipx isolates Python dependencies; it does not install Fail2Ban or host tools or
grant log/sudo permissions. Installation downloads no GeoIP data. Uninstalling
the package does not delete user-owned XDG GeoIP data.

### Migrating from a standalone installation

Migration is additive. Record the old executable path and preserve its files and
Python environment for rollback. Use `command -v offenders` (and Bash's
`type -a offenders`) before and after installation to detect command shadowing.
Check the executable location reported by pipx; deliberately select it through
PATH or its full path when ready to verify `offenders geoip status` and launch.
Keep the same user/XDG environment to retain GeoIP data and policy. Rollback
means restoring the old command resolution and environment; retain the old
installation until the replacement is verified.

### Source and advanced installs

From a checkout, with `python3-venv` available:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
offenders
```

`python -m pip install .` provides a non-editable source install;
`pipx install .` provides local application isolation. With the source environment
active, `python offenders.py` or `./offenders.py` also launches the dashboard.
Keep the packaged modules together: copying only the old single script is not a
current installation method. See [development](https://github.com/stef-k/Offenders/blob/master/DEVELOPMENT.md)
for contributor setup and artifact checks.
