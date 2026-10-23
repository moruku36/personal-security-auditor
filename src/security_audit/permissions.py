"""Platform-aware metadata checks. Windows ACLs and Linux modes are never changed."""
from __future__ import annotations

from pathlib import Path

from security_audit.safety import mode
from security_audit.windows import broad_windows_acl


def broad_access(path: Path, system: str) -> bool | None:
    if path.is_symlink() or not path.exists():
        return None
    if system == "Windows":
        return broad_windows_acl(path)
    permission = mode(path)
    return bool(permission & 0o077) if permission is not None else None


def auto_fixable(system: str) -> bool:
    """Only macOS may offer chmod; all other platforms are read-only."""
    return system == "Darwin"
