"""Keep untrusted local names and command output out of reports."""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

SAFE_NAME = re.compile(r"^[a-zA-Z0-9_.@+ -]{1,80}$")


def label(path: Path, home: Path) -> str:
    """Only emit an approved relative path; otherwise a generic placeholder."""
    try:
        relative = path.relative_to(home)
    except ValueError:
        return "[outside home]"
    parts = relative.parts
    if len(parts) > 8 or any(not SAFE_NAME.fullmatch(part) for part in parts):
        return "[redacted path]"
    return "~/" + "/".join(parts)


def mode(path: Path) -> int | None:
    try:
        if path.is_symlink():
            return None
        return path.stat().st_mode & 0o777
    except OSError:
        return None


def run(argv: list[str], timeout: float = 4.0) -> tuple[int, str]:
    """Never return stderr; callers must reduce stdout to fixed vocabulary."""
    try:
        done = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"},
        )
        return done.returncode, done.stdout[:8192]
    except (OSError, subprocess.SubprocessError):
        return -1, ""
