"""Small installed CLI for GeoIP health, explicit updates, and opt-in policy."""
import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

from offenders_geoip import GeoIP, resolve_data_root
from offenders_geoip_update import UpdateError, read_state, set_auto, update


def main(argv=None):
    """Dispatch GeoIP commands; status never writes or starts network work."""
    parser = argparse.ArgumentParser(prog="offenders geoip")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="Show local source health and update policy")
    commands.add_parser("update", help="Download and activate a validated DB-IP pair")
    policy = commands.add_parser("auto", help="Set policy for future automatic checks")
    policy.add_argument("policy", choices=("on", "off"))
    args = parser.parse_args(argv)
    try:
        root = resolve_data_root()
        if args.command == "status":
            service = GeoIP(root)
            try:
                health = service.refresh()
                active_paths = [Path(item.resolved_path) for value in health.values()
                                for item in value.candidates
                                if item.active and item.source == "app-managed"]
                generation = next((path.parent.name for path in active_paths
                                   if path.parent.parent == root.absolute() / "generations"), None)
                state = read_state(root)
                print(json.dumps({
                    "generation": generation,
                    "health": {kind: asdict(value) for kind, value in health.items()},
                    "auto": state.get("auto") is True,
                    "last_check": state.get("last_check"),
                    "outcome": state.get("outcome", "never checked"),
                }, indent=2))
            finally:
                service.close()
        elif args.command == "update":
            print(f"GeoIP activated: {update(root)}")
        else:
            set_auto(args.policy == "on", root)
            print(f"GeoIP automatic updates: {args.policy}")
        return 0
    except (UpdateError, OSError, RuntimeError) as error:
        print(f"GeoIP: {error}", file=sys.stderr)
        return 1
