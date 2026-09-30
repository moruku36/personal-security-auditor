from __future__ import annotations

import shutil

from security_audit.model import Finding, Risk
from security_audit.safety import mode
from security_audit.scanners.base import Context


class CloudScanner:
    category = "cloud"

    def detect(self, context: Context) -> bool:
        return True

    def recommendations(self) -> tuple[str, ...]:
        return ("Prefer short-lived SSO credentials to static cloud access keys.",)

    def scan(self, context: Context) -> list[Finding]:
        findings: list[Finding] = []
        for tool in ("aws", "az", "gcloud"):
            if shutil.which(tool):
                findings.append(Finding("CL-001", Risk.INFO, f"{tool} CLI detected", tool,
                                        "Review account privileges and credential age in the provider console."))
        for relative, provider in ((".aws/credentials", "AWS"),
                                   (".azure/accessTokens.json", "Azure"),
                                   (".config/gcloud/application_default_credentials.json", "GCP")):
            path = context.home / relative
            permission = mode(path)
            if permission is None:
                continue
            findings.append(Finding("CL-002", Risk.MEDIUM, f"{provider} credential file exists",
                                    "~/" + relative, "Review whether this local credential is needed."))
            if permission & 0o077:
                findings.append(Finding("CL-003", Risk.HIGH,
                    f"{provider} credential file permissions are broad", "~/" + relative,
                    "Restrict mode to 0600 after reviewing access needs.", True))
        return findings
