"""Credential-file presence checks that never read file contents."""
from __future__ import annotations

import itertools
import os
import stat
from pathlib import Path

from security_audit.model import Finding, Risk
from security_audit.permissions import broad_access
from security_audit.scanners.base import Context


def is_regular_file_without_following_links(path: Path) -> bool:
    """Check file metadata only; never open or follow a candidate file."""
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return stat.S_ISREG(metadata.st_mode)


class SecretScanner:
    category = "api"

    def detect(self, context: Context) -> bool:
        return True

    def recommendations(self) -> tuple[str, ...]:
        return ("Review likely credential files locally; this scan does not read their contents.",)

    def scan(self, context: Context) -> list[Finding]:
        home = context.home
        shell_files = [home / name for name in (".zshrc", ".bashrc", ".bash_profile", ".profile")]
        if context.system == "Windows":
            shell_files.extend(home / name for name in (
                "Documents/PowerShell/Microsoft.PowerShell_profile.ps1",
                "Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1"))
        env_files = [home / ".env"]
        try:
            env_files.extend(path for path in itertools.islice(home.glob(".env.*"), 20)
                             if not path.name.endswith(".example"))
            env_files.extend(path for path in itertools.islice(context.repository.glob(".env*"), 20)
                             if not path.name.endswith(".example"))
        except OSError:
            pass

        shell_count = sum(is_regular_file_without_following_links(path)
                          for path in dict.fromkeys(shell_files))
        unique_env_files = list(dict.fromkeys(env_files))
        existing_env_files = [path for path in unique_env_files
                              if is_regular_file_without_following_links(path)]
        findings: list[Finding] = []
        if shell_count or existing_env_files:
            findings.append(Finding("API-001", Risk.INFO,
                f"{shell_count + len(existing_env_files)} selected configuration file(s) found; "
                "contents were not read",
                "local configuration metadata",
                "Review likely credential files locally without sharing their contents."))

        for path in existing_env_files:
            exposure = broad_access(path, context.system)
            if exposure:
                findings.append(Finding("API-002", Risk.HIGH,
                    "An environment configuration file is accessible to others",
                    "local environment-file permissions",
                    "Review who needs access and restrict permissions if appropriate.",
                    False))
            elif exposure is None:
                findings.append(Finding("API-098", Risk.INFO,
                    "Environment configuration file permissions unavailable",
                    "local environment-file permissions",
                    "Review file permissions manually."))

        secret_words = ("TOKEN", "SECRET", "PASSWORD", "API_KEY", "ACCESS_KEY", "PRIVATE_KEY")
        count = sum(1 for key in os.environ if any(word in key.upper() for word in secret_words))
        if count:
            findings.append(Finding("API-003", Risk.INFO,
                f"{count} secret-like environment variable name(s) detected",
                "process environment",
                "Review how these values are injected; no values were accessed."))
        return findings
