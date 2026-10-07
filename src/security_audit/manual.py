"""Aggregate user reports only: never open browser authentication stores."""
from __future__ import annotations

import json
import re
import stat
from datetime import date
from pathlib import Path

from security_audit.model import Evidence, Finding, Risk, Status
from security_audit.reporting import _has_reparse_ancestor, write_private
from security_audit.scanners.base import Context

RESULTS = ("clear", "issues", "unchecked")
BROWSERS = ("Chrome", "Brave", "Edge", "Firefox", "Safari")
MAX_RECORD_BYTES = 512
PASSWORD_GUIDE = (
    "In Chrome, open Google Password Manager > Checkup "
    "(chrome://password-manager/checkup). Review compromised, weak and reused passwords. "
    "Alternatively visit https://passwords.google.com/ and select Checkup. "
    "Record only clear, issues or unchecked; do not enter passwords, sites or account names."
)
EXTENSION_GUIDE = (
    "In the browser UI, review enabled extensions, their effective permissions/site access "
    "and publisher information. Record only an aggregate result; do not enter extension "
    "names, IDs, sites or account names."
)


def record_path(home: Path, kind: str, browser: str = "Chrome") -> Path:
    if kind == "password":
        name = "password-checkup.json"
    elif kind == "extensions" and browser in BROWSERS:
        name = "extensions-" + browser.lower() + ".json"
    else:
        raise ValueError("Unsupported manual check")
    return home / ".security-audit" / name


def validate_date(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError("Invalid check date")
    parsed = date.fromisoformat(value)
    if parsed > date.today():
        raise ValueError("Check date is in the future")
    return value


def read_bounded_json(path: Path, limit: int) -> object:
    if _has_reparse_ancestor(path):
        raise ValueError("State path contains a link or reparse point")
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
        raise ValueError("Invalid state file")
    with path.open("r", encoding="utf-8") as handle:
        content = handle.read(limit + 1)
    if len(content.encode("utf-8")) > limit:
        raise ValueError("State file exceeds limit")
    return json.loads(content)


def read_record(path: Path) -> tuple[Status, str | None]:
    try:
        value = read_bounded_json(path, MAX_RECORD_BYTES)
    except FileNotFoundError:
        return Status.UNKNOWN, None
    except (OSError, ValueError, UnicodeError, RecursionError):
        return Status.UNAVAILABLE, None
    if not isinstance(value, dict) or set(value) != {"result", "checked_on"}:
        return Status.UNAVAILABLE, None
    result = value["result"]
    if not isinstance(result, str) or result not in RESULTS:
        return Status.UNAVAILABLE, None
    if result == "unchecked":
        return ((Status.UNKNOWN, None) if value["checked_on"] is None
                else (Status.UNAVAILABLE, None))
    try:
        checked_on = validate_date(value["checked_on"])
    except ValueError:
        return Status.UNAVAILABLE, None
    return (Status.PASS if result == "clear" else Status.ISSUE), checked_on


def save_record(path: Path, result: str, checked_on: str | None = None) -> None:
    if _has_reparse_ancestor(path.parent):
        raise ValueError("State path contains a link or reparse point")
    if result not in RESULTS:
        raise ValueError("Unsupported result")
    if result == "unchecked":
        if checked_on is not None:
            raise ValueError("Unchecked has no check date")
    else:
        checked_on = validate_date(checked_on or date.today().isoformat())
    write_private(path, json.dumps({"result": result, "checked_on": checked_on}) + "\n")


def forget_record(path: Path) -> None:
    if _has_reparse_ancestor(path):
        raise ValueError("State path contains a link or reparse point")
    path.unlink(missing_ok=True)


def manual_finding(context: Context, kind: str, browser: str = "Chrome") -> Finding:
    status, checked_on = read_record(record_path(context.home, kind, browser))
    password = kind == "password"
    subject = "Google Password Checkup" if password else browser + " effective extension review"
    labels = {Status.PASS: "user reported no issues", Status.ISSUE: "user reported issues",
              Status.UNKNOWN: "not checked", Status.UNAVAILABLE: "local record unavailable"}
    return Finding(
        "BR-011" if password else "BR-012",
        Risk.MEDIUM if status == Status.ISSUE else Risk.INFO,
        subject + ": " + labels[status], subject,
        PASSWORD_GUIDE if password else EXTENSION_GUIDE,
        status=status,
        evidence_source=(Evidence.UNAVAILABLE if status == Status.UNAVAILABLE else
                         Evidence.MANUAL if status == Status.UNKNOWN else Evidence.USER_UI),
        limitations=("User-reported aggregate result; the CLI does not verify browser UI or accounts.",
                     "Valid only for the date and browser/profile/account scope the user reviewed.",
                     "An old clear result is not a current safety guarantee."),
        checked_on=checked_on,
    )
