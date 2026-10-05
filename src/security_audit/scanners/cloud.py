from __future__ import annotations

import shutil

from security_audit.model import Finding, Risk
from security_audit.permissions import broad_access
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
        credentials = [(".aws/credentials", "AWS"),
                       (".azure/accessTokens.json", "Azure"),
                       (".config/gcloud/application_default_credentials.json", "GCP")]
        if context.system == "Windows":
            credentials.append(("AppData/Roaming/gcloud/application_default_credentials.json", "GCP"))
        for relative, provider in credentials:
            path = context.home / relative
            if not path.is_file() or path.is_symlink():
                continue
            findings.append(Finding("CL-002", Risk.MEDIUM, f"{provider} credential file exists",
                                    "~/" + relative, "Review whether this local credential is needed."))
            exposure = broad_access(path, context.system)
            if exposure:
                findings.append(Finding("CL-003", Risk.HIGH,
                    f"{provider} credential file permissions are broad", "~/" + relative,
                    "Restrict access to your account after reviewing access needs.",
                    context.system != "Windows"))
            elif exposure is None:
                findings.append(Finding("CL-098", Risk.INFO,
                    f"{provider} credential permissions unavailable", "~/" + relative,
                    "Review file permissions manually."))
        return findings
