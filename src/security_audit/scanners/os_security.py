from __future__ import annotations

import os

from security_audit import linux
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
        if context.system == "Linux":
            return self._scan_linux(context)
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

    def _scan_linux(self, context: Context) -> list[Finding]:
        """Read-only Linux checks; see docs/linux.md for sources and unsupported cases."""
        source = context.linux
        settings = ("Disk encryption", "Firewall", "Mandatory access control",
                    "Secure Boot", "SSH server")
        codes = ("OS-L01", "OS-L02", "OS-L03", "OS-L04", "OS-L05")
        if linux.is_wsl(source):
            return [_linux_finding(
                code, Risk.INFO, f"{setting} is not assessed inside WSL", setting,
                "Run the Windows checks on the Windows host instead.",
                Status.UNAVAILABLE, Evidence.UNAVAILABLE,
                "not_supported: the WSL guest does not own host disk, firewall or firmware state.")
                for code, setting in zip(codes, settings, strict=True)]
        return [
            _disk_encryption_finding(linux.disk_encryption(source)),
            _firewall_finding(linux.firewall_state(source)),
            _mac_finding(linux.mandatory_access_control(source)),
            _secure_boot_finding(linux.secure_boot(source)),
            _ssh_finding(linux.ssh_server_state(source)),
        ]


def _linux_finding(code: str, risk: Risk, title: str, setting: str, recommendation: str,
                   status: Status, evidence: Evidence, *limitations: str) -> Finding:
    return Finding(code, risk, title, setting, recommendation, status=status,
                   evidence_source=evidence, limitations=limitations)


def _unknown(code: str, setting: str, reason: str) -> Finding:
    return _linux_finding(
        code, Risk.INFO, f"{setting} status unknown", setting, f"Review {setting} manually.",
        Status.UNKNOWN, Evidence.UNAVAILABLE, reason)


def _not_supported(code: str, setting: str, reason: str) -> Finding:
    return _linux_finding(
        code, Risk.INFO, f"{setting} status unavailable", setting, f"Review {setting} manually.",
        Status.UNAVAILABLE, Evidence.UNAVAILABLE, "not_supported: " + reason)


def _disk_encryption_finding(state: str) -> Finding:
    code, setting = "OS-L01", "Disk encryption"
    scope = ("Only the block-device stack under the root filesystem is inspected; other "
             "volumes, per-file encryption and recovery key handling are not evaluated.")
    if state == "on":
        return _linux_finding(code, Risk.INFO, "A dm-crypt layer is present under the root filesystem",
                              setting, "Keep disk encryption enabled and protect recovery material.",
                              Status.PASS, Evidence.LOCAL_COMMAND, scope)
    if state == "not_detected":
        return _linux_finding(
            code, Risk.MEDIUM, "No dm-crypt layer was detected under the root filesystem", setting,
            "Confirm whether disk, filesystem or hardware encryption protects this system.",
            Status.NEEDS_REVIEW, Evidence.LOCAL_COMMAND, scope,
            "Hardware self-encrypting drives, fscrypt/eCryptfs, raw dmsetup crypt targets and "
            "encryption below a hypervisor cannot be detected; this is not evidence that data "
            "is unencrypted.")
    if state == "not_supported":
        return _not_supported(code, setting, "the root filesystem is not on a block device this "
                              "adapter can map (for example a container overlay, ZFS or network root).")
    return _unknown(code, setting, "The block-device stack could not be read completely.")


def _firewall_finding(state: str) -> Finding:
    code, setting = "OS-L02", "Firewall"
    scope = ("Only ufw configuration and firewalld status are read; nftables/iptables rule sets "
             "need elevated privileges and are not inspected.")
    if state == "ufw_enabled":
        return _linux_finding(
            code, Risk.INFO, "ufw is configured as enabled", setting,
            "Keep the firewall enabled and review rules periodically.", Status.OBSERVED,
            Evidence.POLICY, scope, "ufw.conf shows configured state, not loaded rules.")
    if state == "firewalld_running":
        return _linux_finding(
            code, Risk.INFO, "firewalld is running", setting,
            "Keep the firewall enabled and review zones periodically.", Status.PASS,
            Evidence.LOCAL_COMMAND, scope, "A running service does not prove the rules are adequate.")
    if state == "manager_disabled":
        return _linux_finding(
            code, Risk.MEDIUM, "A detected firewall manager is not enabled", setting,
            "Review whether another mechanism filters traffic, or enable a firewall.",
            Status.NEEDS_REVIEW, Evidence.LOCAL_COMMAND, scope,
            "Another mechanism (for example hand-written nftables) may still filter traffic.")
    if state == "not_detected":
        return _linux_finding(
            code, Risk.INFO, "No supported firewall manager was detected", setting,
            "Review nftables/iptables or your distribution's firewall tooling manually.",
            Status.UNKNOWN, Evidence.UNAVAILABLE, scope)
    return _unknown(code, setting, "Firewall configuration or status could not be read.")


def _mac_finding(state: str) -> Finding:
    code, setting = "OS-L03", "Mandatory access control"
    scope = "Only the active Linux Security Module list and SELinux mode are read."
    if state == "selinux_enforcing":
        return _linux_finding(code, Risk.INFO, "SELinux is enforcing", setting,
                              "Keep SELinux enforcing.", Status.PASS, Evidence.LOCAL_COMMAND, scope)
    if state == "selinux_permissive":
        return _linux_finding(
            code, Risk.MEDIUM, "SELinux is permissive", setting,
            "Review why SELinux is not enforcing.", Status.NEEDS_REVIEW,
            Evidence.LOCAL_COMMAND, scope)
    if state == "apparmor":
        return _linux_finding(
            code, Risk.INFO, "AppArmor is an active security module", setting,
            "Review profile confinement with your distribution's tools.", Status.OBSERVED,
            Evidence.LOCAL_COMMAND, scope, "Loaded profiles and their modes are not inspected.")
    if state == "none":
        return _linux_finding(
            code, Risk.LOW, "No SELinux or AppArmor module is active", setting,
            "Consider whether another confinement mechanism is in use.", Status.NEEDS_REVIEW,
            Evidence.LOCAL_COMMAND, scope, "Some distributions intentionally ship without one.")
    return _unknown(code, setting, "Active security modules could not be determined.")


def _secure_boot_finding(state: str) -> Finding:
    code, setting = "OS-L04", "Secure Boot"
    scope = "Only the SecureBoot firmware variable is read; key databases and setup mode are not."
    if state == "on":
        return _linux_finding(code, Risk.INFO, "Secure Boot is on", setting,
                              "Keep Secure Boot on and review periodically.", Status.PASS,
                              Evidence.LOCAL_COMMAND, scope)
    if state == "off":
        return _linux_finding(code, Risk.MEDIUM, "Secure Boot is off", setting,
                              "Review and enable Secure Boot in firmware settings if supported.",
                              Status.ISSUE, Evidence.LOCAL_COMMAND, scope)
    if state == "not_supported":
        return _not_supported(code, setting, "the system was not booted through a visible UEFI "
                              "interface (legacy boot, a virtual machine or a container).")
    return _unknown(code, setting, "The firmware variable was missing or unreadable.")


def _ssh_finding(state: str) -> Finding:
    code, setting = "OS-L05", "SSH server"
    scope = "Only systemd state of ssh/sshd service and socket units is read."
    if state == "active":
        return _linux_finding(
            code, Risk.MEDIUM, "An SSH server service or socket is active", setting,
            "Disable it if SSH access is unnecessary.", Status.NEEDS_REVIEW,
            Evidence.LOCAL_COMMAND, scope)
    if state in ("inactive", "not_installed"):
        return _linux_finding(
            code, Risk.INFO, "No SSH server service or socket is active", setting,
            "Enable only if remote SSH access is needed.", Status.PASS,
            Evidence.LOCAL_COMMAND, scope,
            "Servers not managed by these systemd units are not detected.")
    if state == "not_supported":
        return _not_supported(code, setting, "systemd is not the running init system; use the "
                              "listener check for port exposure.")
    return _unknown(code, setting, "systemd could not be queried.")
