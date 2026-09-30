from __future__ import annotations

from security_audit.model import Finding, Risk
from security_audit.safety import label, mode
from security_audit.scanners.base import Context


class SSHScanner:
    category = "ssh"

    def detect(self, context: Context) -> bool:
        return (context.home / ".ssh").is_dir()

    def recommendations(self) -> tuple[str, ...]:
        return ("Keep private keys readable only by their owner.",)

    def scan(self, context: Context) -> list[Finding]:
        root = context.home / ".ssh"
        findings: list[Finding] = []
        root_mode = mode(root)
        if root_mode is not None and root_mode & 0o077:
            findings.append(Finding("SSH-001", Risk.HIGH, "SSH directory permissions are broad",
                "~/.ssh", "Restrict directory mode to 0700 after reviewing access needs.", True))
        try:
            entries = list(root.iterdir())[:200]
        except OSError:
            return findings
        for path in entries:
            if not path.is_file() or path.is_symlink():
                continue
            filename = path.name
            if filename.startswith("id_") and not filename.endswith(".pub"):
                permission = mode(path)
                if permission is not None and permission & 0o077:
                    findings.append(Finding("SSH-002", Risk.HIGH, "SSH private key permissions are broad",
                        label(path, context.home), "Restrict key mode to 0600 after reviewing access needs.", True))
        return findings
