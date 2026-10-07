from __future__ import annotations

from dataclasses import replace

from security_audit.model import Evidence, Finding, Risk, Status, sort_findings
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
        if (category is None or scanner.category == category):
            try:
                if not scanner.detect(context):
                    continue
                findings.extend(_describe(item, scanner.category) for item in scanner.scan(context))
            except (OSError, ValueError, PermissionError):
                findings.append(Finding("SCAN-000", Risk.INFO,
                                        f"{scanner.category} scan was incomplete", scanner.category,
                                        "Review this category manually.", status=Status.UNAVAILABLE,
                                        evidence_source=Evidence.UNAVAILABLE,
                                        category=scanner.category,
                                        limitations=("Scanner detection or inspection failed.",)))
    return sort_findings(findings)


def _describe(item: Finding, category: str) -> Finding:
    """Add bounded evidence labels to legacy scanners without parsing prose."""
    if category in ("os", "browser"):
        return item
    unavailable = {"API-098", "SSH-098", "CL-098", "DEV-098", "AI-098", "NET-000"}
    issues = {"API-002", "SSH-001", "SSH-002", "CL-003", "DEV-003", "AI-002", "GIT-001"}
    permission_codes = {"API-002", "SSH-001", "SSH-002", "CL-003", "DEV-003", "AI-002"}
    if item.code in unavailable:
        return replace(item, category=category, status=Status.UNAVAILABLE,
                       evidence_source=Evidence.UNAVAILABLE,
                       limitations=("This check was inaccessible or its adapter is unavailable.",))
    if item.code == "GIT-002":
        return replace(item, category=category, status=Status.UNKNOWN,
                       evidence_source=Evidence.MANUAL,
                       limitations=("Git history contents were not inspected.",))
    evidence = (Evidence.PERMISSIONS if item.code in permission_codes else
                Evidence.LOCAL_COMMAND if category == "network" else Evidence.METADATA)
    status = (Status.ISSUE if item.code in issues else
              Status.NEEDS_REVIEW if item.code in {"NET-001", "CL-002"} else Status.OBSERVED)
    limitation = ("Listening beyond loopback does not establish Internet exposure."
                  if category == "network" else
                  "Metadata/permission checks do not validate credential values or account protection.")
    return replace(item, category=category, status=status,
                   evidence_source=evidence, limitations=(limitation,))
