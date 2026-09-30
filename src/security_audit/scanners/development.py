"""Development tool and credential-store metadata checks."""
from __future__ import annotations

import shutil

from security_audit.model import Finding, Risk
from security_audit.safety import mode
from security_audit.scanners.base import Context


class DevelopmentScanner:
    category = "dev"
    TOOLS = ("docker", "npm", "pip", "uv", "poetry", "brew", "node",
             "python3", "git", "gh", "code", "codex", "claude")
    CREDENTIAL_FILES = (
        (".npmrc", "npm"),
        (".pypirc", "PyPI"),
        (".docker/config.json", "Docker"),
        (".config/gh/hosts.yml", "GitHub CLI"),
    )

    def detect(self, context: Context) -> bool:
        return True

    def recommendations(self) -> tuple[str, ...]:
        return ("Keep developer tools updated and review local credential stores.",)

    def scan(self, context: Context) -> list[Finding]:
        findings: list[Finding] = []
        installed = [tool for tool in self.TOOLS if shutil.which(tool)]
        if installed:
            findings.append(Finding("DEV-001", Risk.INFO,
                f"{len(installed)} developer CLI tool(s) detected", "PATH",
                "Review installed tool versions and remove unused tools manually."))
        for relative, product in self.CREDENTIAL_FILES:
            path = context.home / relative
            permission = mode(path)
            if permission is None:
                continue
            findings.append(Finding("DEV-002", Risk.INFO,
                f"{product} local configuration file exists", "~/" + relative,
                "Review whether this credential store is still needed."))
            if permission & 0o077:
                findings.append(Finding("DEV-003", Risk.HIGH,
                    f"{product} configuration is accessible to others", "~/" + relative,
                    "Restrict file permissions after reviewing access needs.", True))
        return findings
