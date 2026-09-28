"""Concise local Help prose and startup-only installed package metadata."""
from importlib import metadata

from textual.binding import Binding

from offenders_report import DEFAULT_PERIOD, PERIODS

# Shared by the app and product modals, whose native footer excludes app bindings.
HELP_BINDING = Binding("question_mark", "app.help", "Help", key_display="?", priority=True)

# Source development may have no installed distribution; never fetch these URLs.
PROJECT_URLS = {
    "Documentation": "https://stef-k.github.io/Offenders/",
    "Source": "https://github.com/stef-k/Offenders",
    "Issues": "https://github.com/stef-k/Offenders/issues",
    "PyPI": "https://pypi.org/project/offenders/",
}


def project_information() -> str:
    """Read metadata once at app construction, with a bounded offline fallback."""
    version, urls = "Unavailable (source development)", dict(PROJECT_URLS)
    try:
        package = metadata.metadata("offenders")
        version = package.get("Version") or version
        for entry in package.get_all("Project-URL", []):
            label, separator, url = entry.partition(",")
            if separator and label.strip() in urls and url.strip():
                urls[label.strip()] = url.strip()
    except (metadata.PackageNotFoundError, OSError, ValueError, TypeError):
        pass
    return "\n".join((f"Version: {version[:128]}",
                      *(f"{label}: {url[:2048]}" for label, url in urls.items())))


def product_guide(bindings) -> str:
    """Keep one mini-manual; derive period choices from the report authority."""
    keys = {binding.action: binding.key_display or binding.key
            for binding in Binding.make_bindings(bindings)}
    return f"""Quick concepts
Offenders is a read-only Fail2Ban reporting/investigation tool. The selected historical period and current live jail state describe different facts.
Reports refresh automatically; a failed refresh preserves the last successful snapshot. The dashboard filter changes visibility only; Unavailable is different from valid zero/empty.
The shared ⏳ footer indicates accepted background work without delaying results; (+N) means more work overlaps.

Dashboard
Periods: {', '.join(PERIODS)} (default: {DEFAULT_PERIOD}); finite periods are rolling windows, while all uses available history. Cycle IP / ASN / Country summaries, filter visible data, and open selected real IPs or active jails.
Copy the selected row/cell and switch row/cell cursor mode. Dashboard controls also lead to Export, GeoIP, Coverage and explicit Registration/RDNS lookups.

Investigation
Jail detail separates live counters/membership from selected-period historical bans; expanding history uses retained events without reacquiring data. Navigate jail ↔ IP through selected table rows.
The IP inspector combines committed historical facts, current membership and local GeoIP projection. Registration/RDNS are explicit, separate network actions.

Export
TUI {keys["export"]} Export writes the committed report captured when Export was opened, with no new report acquisition. Dashboard filter and summary mode do not change its contents.
The CSV bundle contains report.csv, top-offenders.csv, jail-status.csv and ban-events.csv. The default root is ~/offenders-exports/; the exact successful path remains visible and copyable.
CLI Export instead builds one fresh report and exits; external Usage documentation defines the CSV schemas.

GeoIP
Optional local Country/ASN enrichment; installation downloads no databases. Update now explicitly downloads and validates app-managed generations before activation; automatic update checks are opt-in.
Unmapped means a healthy database has no matching entry; unavailable means enrichment could not be obtained.

Registration and RDNS
{keys["registration"]} Registration uses RDAP; {keys["rdns"]} RDNS uses reverse DNS/PTR. Both are explicit network requests; non-global Registration skips network traffic.
Results are bounded factual lookup output, not reputation scoring.

Coverage and validation
Coverage is manually initiated and conservatively correlates retained evidence for review. Existing-filter validation tests selected filters against retained samples; custom candidates use fixed templates and validation, remain disabled and copy-only, and are never installed or enabled automatically.
Findings do not prove maliciousness, safety or reachability; sample matches do not establish operational suitability.

Command line
offenders
  Open the TUI.
offenders export [--period PERIOD] [--output-dir PATH]
  Build one fresh report, export the same four-file CSV bundle and exit.
  PERIOD: {', '.join(PERIODS)}; default: {DEFAULT_PERIOD}.
offenders geoip status
  Show local GeoIP source health and update policy.
offenders geoip update
  Explicitly download/validate/activate a GeoIP pair.
offenders geoip auto on|off
  Set the opt-in automatic-update policy.

Important semantics / safety
• Historical bans != current banned membership.
• Unavailable != zero/empty; GeoIP unmapped != unavailable.
• Dashboard filtering changes visibility only; TUI Export uses committed unfiltered report data.
• CLI Export performs one fresh normal report acquisition.
• Registration/RDNS are explicit network actions.
• Coverage findings do not prove maliciousness or safety; filter validation does not prove operational suitability.
• Offenders never bans/unbans addresses or installs/enables/reloads Fail2Ban configuration.

More help
External documentation is authoritative for installation, permissions, CSV schemas, architecture, troubleshooting and deeper operational semantics."""
