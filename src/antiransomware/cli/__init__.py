"""Package CLI entry points."""

from __future__ import annotations

import argparse
import sys
from contextlib import contextmanager
from typing import Sequence

from antiransomware.api.dashboard import main as dashboard_main
from antiransomware.cli.check_events import main as events_main
from antiransomware.cli.deploy_monitor import main as deploy_main
from antiransomware.cli.kill_switch import main as kill_main
from antiransomware.cli.protect_files import main as protect_main


@contextmanager
def _forward_argv(command: str, remainder: Sequence[str]):
    original = sys.argv[:]
    sys.argv = [f"antiransomware {command}", *remainder]
    try:
        yield
    finally:
        sys.argv = original


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="antiransomware", description="Anti-Ransomware command line")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("protect", help="Manage protected paths")
    sub.add_parser("events", help="Query security events")
    sub.add_parser("kill", help="Emergency kill switch")
    sub.add_parser("deploy", help="Deployment and health checks")
    sub.add_parser("dashboard", help="Render dashboard status")

    args, remainder = parser.parse_known_args(argv)

    if args.command == "protect":
        with _forward_argv("protect", remainder):
            return protect_main()
    if args.command == "events":
        with _forward_argv("events", remainder):
            return events_main()
    if args.command == "kill":
        with _forward_argv("kill", remainder):
            return kill_main()
    if args.command == "deploy":
        with _forward_argv("deploy", remainder):
            return deploy_main()
    if args.command == "dashboard":
        with _forward_argv("dashboard", remainder):
            return dashboard_main()

    parser.print_help()
    return 0


__all__ = ["main"]
