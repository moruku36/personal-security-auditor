from __future__ import annotations

import os

from security_audit.model import Evidence, Finding, Risk, Status
from security_audit.safety import run
from security_audit.scanners.base import Context
from security_audit.windows import powershell_json

WINDOWS_STATUS_SCRIPT = r"""
$result = [ordered]@{ encryption='unknown'; firewall='unknown'; antivirus='unknown'; uac='unknown'; secure_boot='unknown' }
try {
  $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
  $result.encryption = if ($volume.ProtectionStatus.ToString() -eq 'On') { 'on' } else { 'off' }
} catch { }
try {
  $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
  $active = @(Get-NetConnectionProfile -ErrorAction Stop | ForEach-Object {
    if ($_.NetworkCategory.ToString() -eq 'DomainAuthenticated') { 'Domain' }
    else { $_.NetworkCategory.ToString() }
  })
  if ($profiles.Count -gt 0) {
    $disabled = @($profiles | Where-Object { -not $_.Enabled })
    $activeDisabled = @($disabled | Where-Object { $active -contains $_.Name })
    if ($activeDisabled.Count -gt 0) { $result.firewall = 'off' }
    elseif ($disabled.Count -gt 0) { $result.firewall = 'off_inactive' }
    else { $result.firewall = 'on' }
  }
} catch { }
try {
  $defender = Get-MpComputerStatus -ErrorAction Stop
  if ($defender.RealTimeProtectionEnabled) { $result.antivirus = 'on' }
  elseif ($defender.AMRunningMode.ToString() -match 'Passive') { $result.antivirus = 'passive' }
  else { $result.antivirus = 'off' }
} catch { }
try {
  $value = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction Stop).EnableLUA
  $result.uac = if ($value -eq 1) { 'on' } else { 'off' }
} catch { }
try {
  $result.secure_boot = if (Confirm-SecureBootUEFI -ErrorAction Stop) { 'on' } else { 'off' }
} catch { }
[pscustomobject]$result | ConvertTo-Json -Compress
"""


class OSScanner:
    category = "os"

    def detect(self, context: Context) -> bool:
        return True

    def recommendations(self) -> tuple[str, ...]:
        return ("Keep the OS updated and enable disk encryption and firewall.",)

    def scan(self, context: Context) -> list[Finding]:
        if context.system == "Windows":
            return self._scan_windows()
        if context.system != "Darwin":
            return [Finding("OS-000", Risk.INFO, "OS adapter is unavailable", "OS",
                            "Review OS security settings manually.", status=Status.UNAVAILABLE,
                            evidence_source=Evidence.UNAVAILABLE)]
        findings: list[Finding] = []
        checks = [
            ("OS-001", ["/usr/bin/fdesetup", "status"], "FileVault is disabled", "FileVault"),
            ("OS-002", ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"], "Firewall is disabled", "Firewall"),
            ("OS-003", ["/usr/sbin/spctl", "--status"], "Gatekeeper is disabled", "Gatekeeper"),
            ("OS-004", ["/usr/bin/csrutil", "status"], "System Integrity Protection is disabled", "SIP"),
        ]
        for code, command, title, setting in checks:
            if code == "OS-002" and os.environ.get("CODEX_SANDBOX"):
                findings.append(Finding(code, Risk.INFO,
                                        "Firewall status unavailable in sandbox", setting,
                                        "Review Firewall outside the sandbox or in macOS settings.",
                                        status=Status.UNAVAILABLE,
                                        evidence_source=Evidence.UNAVAILABLE,
                                        limitations=("The sandbox prevents this check.",)))
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
            if disabled and status == 0:
                findings.append(Finding(code, Risk.HIGH, title, setting,
                                        f"Review and enable {setting} in macOS settings.",
                                        status=Status.ISSUE,
                                        evidence_source=Evidence.LOCAL_COMMAND))
            elif not known or status != 0:
                findings.append(Finding(code, Risk.INFO, f"{setting} status unavailable",
                                        setting, f"Review {setting} manually.",
                                        status=Status.UNAVAILABLE,
                                        evidence_source=Evidence.UNAVAILABLE,
                                        limitations=("Local command did not provide a recognized state.",)))
            else:
                findings.append(Finding(code, Risk.INFO, f"{setting} is enabled", setting,
                                        f"Keep {setting} enabled and review periodically.",
                                        status=Status.PASS,
                                        evidence_source=Evidence.LOCAL_COMMAND))
        status, output = run(["/usr/sbin/systemsetup", "-getremotelogin"])
        if status == 0 and "remote login: on" in output.lower():
            findings.append(Finding("OS-005", Risk.MEDIUM, "Remote Login is enabled",
                                    "Remote Login", "Disable it if SSH access is unnecessary.",
                                    status=Status.NEEDS_REVIEW,
                                    evidence_source=Evidence.LOCAL_COMMAND))
        elif status == 0 and "remote login: off" in output.lower():
            findings.append(Finding("OS-005", Risk.INFO, "Remote Login is disabled",
                                    "Remote Login", "Enable only if remote SSH access is needed.",
                                    status=Status.PASS, evidence_source=Evidence.LOCAL_COMMAND))
        else:
            findings.append(Finding("OS-005", Risk.INFO, "Remote Login status unavailable",
                                    "Remote Login", "Review Remote Login in macOS settings.",
                                    status=Status.UNAVAILABLE,
                                    evidence_source=Evidence.UNAVAILABLE))
        return findings

    def _scan_windows(self) -> list[Finding]:
        status = powershell_json(WINDOWS_STATUS_SCRIPT)
        if not isinstance(status, dict):
            status = {}

        checks = (
            ("encryption", "OS-W01", Risk.HIGH, "System drive encryption is off", "BitLocker or Device Encryption"),
            ("firewall", "OS-W02", Risk.HIGH, "Active Windows Firewall profile is off", "Windows Firewall"),
            ("antivirus", "OS-W03", Risk.HIGH, "Microsoft Defender real-time protection is off", "Microsoft Defender"),
            ("uac", "OS-W04", Risk.HIGH, "User Account Control is off", "UAC"),
            ("secure_boot", "OS-W05", Risk.MEDIUM, "Secure Boot is off", "Secure Boot"),
        )
        findings: list[Finding] = []
        for key, code, risk, title, setting in checks:
            value = status.get(key)
            if value == "off":
                findings.append(Finding(code, risk, title, setting,
                                        f"Review and enable {setting} in Windows settings.",
                                        status=Status.ISSUE,
                                        evidence_source=Evidence.LOCAL_COMMAND))
            elif key == "firewall" and value == "off_inactive":
                findings.append(Finding(code, Risk.MEDIUM,
                    "An inactive Windows Firewall profile is off", setting,
                    "Enable all firewall profiles before using another network.",
                    status=Status.ISSUE, evidence_source=Evidence.LOCAL_COMMAND))
            elif key == "antivirus" and value == "passive":
                findings.append(Finding(code, Risk.INFO,
                    "Microsoft Defender is passive", setting,
                    "Verify that another antivirus product provides real-time protection.",
                    status=Status.NEEDS_REVIEW, evidence_source=Evidence.LOCAL_COMMAND))
            elif value != "on":
                findings.append(Finding(code, Risk.INFO, f"{setting} status unavailable",
                                        setting, f"Review {setting} in Windows Security.",
                                        status=Status.UNAVAILABLE,
                                        evidence_source=Evidence.UNAVAILABLE,
                                        limitations=("The probe was inaccessible or returned unknown data.",)))
            else:
                findings.append(Finding(code, Risk.INFO, f"{setting} is on", setting,
                                        f"Keep {setting} on and review periodically.",
                                        status=Status.PASS,
                                        evidence_source=Evidence.LOCAL_COMMAND))
        return findings
