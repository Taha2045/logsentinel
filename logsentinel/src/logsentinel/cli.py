"""Command-line interface."""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from . import __version__
from .detectors import analyze
from .parsers import parse_access, parse_ssh
from .report import to_json, to_markdown


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="logsentinel", description="SOC log analyzer mapped to MITRE ATT&CK")
    p.add_argument("--ssh", type=Path, help="OpenSSH auth.log file")
    p.add_argument("--web", type=Path, help="Apache/Nginx combined access.log file")
    p.add_argument("--year", type=int, default=datetime.now().year, help="year for syslog timestamps")
    p.add_argument("--threshold", type=int, default=5, help="failed logins to trigger a detection")
    p.add_argument("--window", type=int, default=300, help="time window in seconds")
    p.add_argument("--format", choices=["md", "json"], default="md")
    p.add_argument("-o", "--output", type=Path, help="write report to file")
    p.add_argument("--fail-on", choices=["medium", "high", "critical"],
                   help="exit with code 1 if findings at/above this severity exist")
    p.add_argument("--version", action="version", version=__version__)
    args = p.parse_args(argv)

    if not args.ssh and not args.web:
        p.error("provide at least one of --ssh / --web")

    events = []
    if args.ssh:
        events += list(parse_ssh(args.ssh.read_text(errors="replace").splitlines(), args.year))
    if args.web:
        events += list(parse_access(args.web.read_text(errors="replace").splitlines()))

    findings = analyze(events, args.threshold, args.window)
    report = (to_json if args.format == "json" else to_markdown)(findings, len(events))
    if args.output:
        args.output.write_text(report, encoding="utf-8")
        print(f"Report written to {args.output} ({len(findings)} findings)")
    else:
        print(report)

    if args.fail_on:
        order = {"medium": 2, "high": 1, "critical": 0}
        from .detectors import SEVERITY_ORDER
        if any(SEVERITY_ORDER[f.severity] <= order[args.fail_on] for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
