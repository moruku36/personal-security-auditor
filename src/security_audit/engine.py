from __future__ import annotations

from security_audit.model import Finding, Risk, sort_findings
from security_audit.scanners.ai_agents import AIAgentScanner
from security_audit.scanners.base import Context, Scanner
from security_audit.scanners.browser import BrowserScanner
from security_audit.scanners.cloud import CloudScanner
from security_audit.scanners.development import DevelopmentScanner
from security_audit.scanners.git import GitScanner
from security_audit.scanners.network import NetworkScanner
from security_audit.scanners.os_security import OSScanner
from security_audit.scanners.secrets import SecretScanner
from security_audit.scanners.ssh import SSHScanner

SCANNERS: tuple[Scanner, ...] = (
    OSScanner(), BrowserScanner(), SecretScanner(), GitScanner(), SSHScanner(),
    CloudScanner(), DevelopmentScanner(), NetworkScanner(), AIAgentScanner(),
)
CATEGORIES = {scanner.category for scanner in SCANNERS}


def scan(context: Context, category: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for scanner in SCANNERS:
        if (category is None or scanner.category == category) and scanner.detect(context):
            try:
                findings.extend(scanner.scan(context))
            except (OSError, ValueError, PermissionError):
                findings.append(Finding("SCAN-000", Risk.INFO,
                                        f"{scanner.category} scan was incomplete", scanner.category,
                                        "Review this category manually."))
    return sort_findings(findings)
