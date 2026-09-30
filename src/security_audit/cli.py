from __future__ import annotations

import argparse
import sys
from pathlib import Path

from security_audit.engine import CATEGORIES, scan
from security_audit.remediation import apply_permission, target
from security_audit.reporting import as_json, as_markdown, as_terminal, write_private
from security_audit.safety import label
from security_audit.scanners.base import Context


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="security-audit")
    commands = root.add_subparsers(dest="command", required=True)
    for name in ("scan", "report", "fix"):
        command = commands.add_parser(name)
        command.add_argument("category", nargs="?", choices=sorted(CATEGORIES))
        command.add_argument("--full", action="store_true")
        command.add_argument("--repository", type=Path, default=Path.cwd())
        if name == "report":
            command.add_argument("--format", choices=("terminal", "markdown", "json"),
                                 default="terminal")
            command.add_argument("--output", type=Path)
        if name == "fix":
            command.add_argument("--apply", action="store_true",
                                 help="Apply only listed permission changes")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    context = Context(Path.home(), args.repository.resolve(), args.full)
    findings = scan(context, args.category)
    if args.command == "scan":
        print(as_terminal(findings), end="")
    elif args.command == "report":
        content = {"terminal": as_terminal, "markdown": as_markdown,
                   "json": as_json}[args.format](findings)
        if args.output:
            try:
                write_private(args.output, content)
            except (OSError, ValueError):
                print("Could not write report safely.", file=sys.stderr)
                return 2
            print("Report written with owner-only permissions.")
        else:
            print(content, end="")
    else:
        candidates = [pair for finding in findings if (pair := target(context, finding))]
        for path, desired in candidates:
            print(f"chmod {desired:04o} {label(path, context.home)}")
        if not args.apply:
            print("Dry run. Pass --apply to make these permission changes.")
        else:
            for path, desired in candidates:
                if not apply_permission(path, desired):
                    print("One permission change was skipped.", file=sys.stderr)
            print("Permission changes complete. Rescan to verify.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
