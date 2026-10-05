"""Development tool and credential-store metadata checks."""
from __future__ import annotations

import shutil

from security_audit.model import Finding, Risk
from security_audit.permissions import broad_access
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
        credential_files = list(self.CREDENTIAL_FILES)
        if context.system == "Windows":
            credential_files.append(("AppData/Roaming/GitHub CLI/hosts.yml", "GitHub CLI"))
        for relative, product in credential_files:
            path = context.home / relative
            if not path.is_file() or path.is_symlink():
                continue
            findings.append(Finding("DEV-002", Risk.INFO,
                f"{product} local configuration file exists", "~/" + relative,
                "Review whether this credential store is still needed."))
            exposure = broad_access(path, context.system)
            if exposure:
                findings.append(Finding("DEV-003", Risk.HIGH,
                    f"{product} configuration is accessible to others", "~/" + relative,
                    "Restrict file access after reviewing access needs.",
                    context.system != "Windows"))
            elif exposure is None:
                findings.append(Finding("DEV-098", Risk.INFO,
                    f"{product} permissions unavailable", "~/" + relative,
                    "Review file permissions manually."))
        return findings
