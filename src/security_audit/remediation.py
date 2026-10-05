"""Conservative permission changes only; scan never invokes this module."""
from __future__ import annotations

import os
from pathlib import Path

from security_audit.model import Finding
from security_audit.safety import mode
from security_audit.scanners.base import Context

TARGET_MODES = {"SSH-001": 0o700, "SSH-002": 0o600,
                "API-002": 0o600, "CL-003": 0o600, "DEV-003": 0o600,
                "AI-002": 0o700}


def target(context: Context, finding: Finding) -> tuple[Path, int] | None:
    if context.system == "Windows":
        return None
    desired = TARGET_MODES.get(finding.code)
    if desired is None or not finding.location.startswith("~/"):
        return None
    path = context.home / finding.location[2:]
    if path.is_symlink() or mode(path) is None:
        return None
    return path, desired


def apply_permission(path: Path, desired: int) -> bool:
    fchmod = getattr(os, "fchmod", None)
    if fchmod is None:
        return False
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            current = os.fstat(descriptor).st_mode & 0o777
            fchmod(descriptor, current & desired)
            return True
        finally:
            os.close(descriptor)
    except OSError:
        return False
