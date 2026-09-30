"""Secret presence detection without collecting values."""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from security_audit.model import Finding, Risk
from security_audit.permissions import broad_access
from security_audit.safety import label
from security_audit.scanners.base import Context

KEY = re.compile(rb"^[A-Za-z_][A-Za-z0-9_]{0,79}$")
SECRET_WORDS = (b"TOKEN", b"SECRET", b"PASSWORD", b"API_KEY", b"ACCESS_KEY", b"PRIVATE_KEY")
NON_SECRET = {b"PATH", b"TOKENIZERS_PARALLELISM", b"PASSWORD_STORE_DIR"}


def assignment_names(path: Path) -> set[bytes]:
    """Read only assignment names; skip values byte by byte, never assemble a line."""
    names: set[bytes] = set()
    try:
        metadata = path.stat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1_000_000:
            return names
        with path.open("rb", buffering=0) as handle:
            at_start = True
            name = bytearray()
            collecting = True
            while single := handle.read(1):
                byte = single[0]
                if byte in (10, 13):
                    at_start, collecting = True, True
                    name.clear()
                elif at_start and byte in (32, 9):
                    continue
                elif collecting and byte in (32, 9) and name == b"export":
                    name.clear()
                    at_start = True
                elif collecting and byte == 61:
                    candidate = bytes(name).upper()
                    if candidate.startswith(b"$ENV:"):
                        candidate = candidate[5:]
                    if (KEY.fullmatch(candidate) and candidate not in NON_SECRET
                            and any(word in candidate for word in SECRET_WORDS)):
                        names.add(candidate)
                    collecting = False
                    at_start = False
                    name.clear()
                elif collecting and len(name) < 80 and byte not in (32, 9):
                    name.append(byte)
                    at_start = False
                else:
                    collecting = False
                    at_start = False
                    name.clear()
    except OSError:
        pass
    return names


class SecretScanner:
    category = "api"

    def detect(self, context: Context) -> bool:
        return True

    def recommendations(self) -> tuple[str, ...]:
        return ("Move long-lived credentials to a managed credential store.",)

    def scan(self, context: Context) -> list[Finding]:
        home = context.home
        files = [home / name for name in (".zshrc", ".bashrc", ".bash_profile", ".profile", ".env")]
        if context.system == "Windows":
            files.extend(home / name for name in (
                "Documents/PowerShell/Microsoft.PowerShell_profile.ps1",
                "Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1"))
        files.extend(sorted(home.glob(".env.*"))[:20])
        files.extend(sorted(context.repository.glob(".env*"))[:20])
        findings: list[Finding] = []
        for path in dict.fromkeys(files):
            names = assignment_names(path)
            if names:
                findings.append(Finding("API-001", Risk.HIGH,
                    f"{len(names)} secret-like assignment(s) in a text file",
                    label(path, home), "Review storage and rotate exposed long-lived keys."))
            if names:
                exposure = broad_access(path, context.system)
                if exposure:
                    findings.append(Finding("API-002", Risk.HIGH,
                        "Credential file is accessible to others", label(path, home),
                        "Restrict file access after reviewing access needs.",
                        context.system != "Windows"))
                elif exposure is None:
                    findings.append(Finding("API-098", Risk.INFO,
                        "Credential file permissions unavailable", label(path, home),
                        "Review file permissions manually."))
        count = sum(1 for key in os.environ if any(word.decode() in key.upper() for word in SECRET_WORDS))
        if count:
            findings.append(Finding("API-003", Risk.INFO,
                f"{count} secret-like environment variable name(s) detected", "process environment",
                "Review how these values are injected; no values were accessed."))
        return findings
