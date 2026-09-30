from __future__ import annotations

from security_audit.model import Finding, Risk
from security_audit.permissions import broad_access
from security_audit.safety import label
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
        root_exposure = broad_access(root, context.system)
        if root_exposure:
            findings.append(Finding("SSH-001", Risk.HIGH, "SSH directory permissions are broad",
                "~/.ssh", "Restrict directory access after reviewing access needs.",
                context.system != "Windows"))
        elif root_exposure is None:
            findings.append(Finding("SSH-098", Risk.INFO, "SSH directory permissions unavailable",
                "~/.ssh", "Review directory permissions manually."))
        try:
            entries = list(root.iterdir())[:200]
        except OSError:
            return findings
        for path in entries:
            if not path.is_file() or path.is_symlink():
                continue
            filename = path.name
            if filename.startswith("id_") and not filename.endswith(".pub"):
                exposure = broad_access(path, context.system)
                if exposure:
                    findings.append(Finding("SSH-002", Risk.HIGH, "SSH private key permissions are broad",
                        label(path, context.home), "Restrict key access after reviewing access needs.",
                        context.system != "Windows"))
                elif exposure is None:
                    findings.append(Finding("SSH-098", Risk.INFO,
                        "SSH private key permissions unavailable", label(path, context.home),
                        "Review key permissions manually."))
        return findings
