from __future__ import annotations

import argparse
import sys
from pathlib import Path

from security_audit.comparison import compare, read_snapshot, save_snapshot, snapshot
from security_audit.coverage import as_coverage
from security_audit.engine import CATEGORIES, scan
from security_audit.manual import (
    BROWSERS,
    RESULTS,
    forget_record,
    manual_finding,
    record_path,
    save_record,
)
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
        if name in ("scan", "report"):
            command.add_argument("--snapshot", type=Path,
                                 help="Save an opt-in ID/state snapshot with private permissions")
            command.add_argument("--compare", type=Path,
                                 help="Compare a previous ID/state snapshot with the same scan scope")
        if name == "report":
            command.add_argument("--format", choices=("terminal", "markdown", "json"),
                                 default="terminal")
            command.add_argument("--output", type=Path)
        if name == "fix":
            command.add_argument("--apply", action="store_true",
                                 help="Apply only listed permission changes")
    for name in ("password-checkup", "browser-review"):
        command = commands.add_parser(name)
        if name == "browser-review":
            command.add_argument("browser", choices=BROWSERS)
        selection = command.add_mutually_exclusive_group()
        selection.add_argument("--result", choices=RESULTS,
                               help="clear=no issues; issues=problems found; unchecked=not reviewed")
        selection.add_argument("--forget", action="store_true", help="Remove this local manual record")
        command.add_argument("--date", help="Check date YYYY-MM-DD; default today")
    coverage = commands.add_parser("coverage")
    coverage.add_argument("--format", choices=("terminal", "markdown", "json"), default="terminal")
    return root


def main(argv: list[str] | None = None) -> int:
    root = parser()
    args = root.parse_args(argv)
    if args.command == "coverage":
        print(as_coverage(args.format), end="")
        return 0
    if args.command in ("password-checkup", "browser-review"):
        if args.date is not None and (not args.result or args.result == "unchecked"):
            root.error("--date requires --result clear or issues")
        kind = "password" if args.command == "password-checkup" else "extensions"
        browser = getattr(args, "browser", "Chrome")
        home = Path.home()
        path = record_path(home, kind, browser)
        try:
            if args.forget:
                forget_record(path)
            elif args.result:
                save_record(path, args.result, args.date)
        except (OSError, ValueError, UnicodeError):
            print("Could not update the manual result safely; check date and permissions.",
                  file=sys.stderr)
            return 2
        print(as_terminal([manual_finding(Context(home, Path.cwd()), kind, browser)]), end="")
        return 0
    if (args.command == "report" and args.snapshot and args.output
            and args.snapshot.resolve() == args.output.resolve()):
        root.error("--snapshot and --output must use different files")
    context = Context(Path.home(), args.repository.resolve(), args.full)
    findings = scan(context, args.category)
    if args.command in ("scan", "report") and (args.compare or args.snapshot):
        categories = {args.category} if args.category else CATEGORIES
        try:
            current = snapshot(findings, context, categories)
            if args.compare:
                previous = read_snapshot(args.compare, current.scope)
                # Keep JSON/Markdown report stdout valid; comparison has its own stream.
                print(compare(previous, current), end="", file=sys.stderr)
            if args.snapshot:
                save_snapshot(args.snapshot, current)
        except (OSError, ValueError, UnicodeError, RecursionError):
            print("Could not read, compare or save snapshot safely. Check schema, scope and permissions.",
                  file=sys.stderr)
            return 2
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
