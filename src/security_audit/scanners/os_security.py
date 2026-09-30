from __future__ import annotations

import os
import platform

from security_audit.model import Finding, Risk
from security_audit.safety import run
from security_audit.scanners.base import Context


class OSScanner:
    category = "os"

    def detect(self, context: Context) -> bool:
        return True

    def recommendations(self) -> tuple[str, ...]:
        return ("Keep the OS updated and enable disk encryption and firewall.",)

    def scan(self, context: Context) -> list[Finding]:
        system = platform.system()
        if system != "Darwin":
            return [Finding("OS-000", Risk.INFO, f"{system} adapter is pending", "OS",
                            "Review OS security settings manually.")]
        findings: list[Finding] = []
        checks = [
            ("OS-001", ["/usr/bin/fdesetup", "status"], "FileVault is disabled", "FileVault"),
            ("OS-002", ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"], "Firewall is disabled", "Firewall"),
            ("OS-003", ["/usr/sbin/spctl", "--status"], "Gatekeeper is disabled", "Gatekeeper"),
            ("OS-004", ["/usr/bin/csrutil", "status"], "System Integrity Protection is disabled", "SIP"),
        ]
        for code, command, title, setting in checks:
            if code == "OS-002" and os.environ.get("CODEX_SANDBOX"):
                findings.append(Finding("OS-098", Risk.INFO,
                                        "Firewall status unavailable in sandbox", setting,
                                        "Review Firewall outside the sandbox or in macOS settings."))
                continue
            status, output = run(command)
            value = output.strip().lower()
            known = (
                (code == "OS-001" and ("filevault is on" in value or "filevault is off" in value))
                or (code == "OS-002" and status == 0
                    and ("firewall is enabled" in value or "firewall is disabled" in value))
                or (code == "OS-003" and ("assessments enabled" in value or "assessments disabled" in value))
                or (code == "OS-004" and ("status: enabled" in value or "status: disabled" in value))
            )
            disabled = (
                (code == "OS-001" and "filevault is off" in value)
                or (code == "OS-002" and "firewall is disabled" in value)
                or (code == "OS-003" and "assessments disabled" in value)
                or (code == "OS-004" and "status: disabled" in value)
            )
            if disabled:
                findings.append(Finding(code, Risk.HIGH, title, setting,
                                        f"Review and enable {setting} in macOS settings."))
            elif not known:
                findings.append(Finding("OS-098", Risk.INFO, f"{setting} status unavailable",
                                        setting, f"Review {setting} manually."))
        status, output = run(["/usr/sbin/systemsetup", "-getremotelogin"])
        if status == 0 and "remote login: on" in output.lower():
            findings.append(Finding("OS-005", Risk.MEDIUM, "Remote Login is enabled",
                                    "Remote Login", "Disable it if SSH access is unnecessary."))
        elif "remote login: off" not in output.lower():
            findings.append(Finding("OS-098", Risk.INFO, "Remote Login status unavailable",
                                    "Remote Login", "Review Remote Login in macOS settings."))
        return findings
