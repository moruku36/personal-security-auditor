# Windows checks

Run `security-audit scan --full` in native Windows 10 or 11 with Python 3.11+.
The tool uses built-in Windows PowerShell locally and makes no network request.
Run as a normal user first. Unreadable status is reported as INFO rather than
assumed safe or unsafe.

| Check | Source | Result when unavailable |
| --- | --- | --- |
| System drive protection | `Get-BitLockerVolume` | INFO |
| Active firewall profile | `Get-NetFirewallProfile` and `Get-NetConnectionProfile` | INFO |
| Defender real-time status | `Get-MpComputerStatus` | INFO; passive mode prompts review of other antivirus |
| User Account Control | `EnableLUA` registry policy | INFO |
| Secure Boot | `Confirm-SecureBootUEFI` | INFO; administrator rights may be needed |
| TCP listeners | `Get-NetTCPConnection` | INFO |
| Credential, SSH and agent ACLs | `Get-Acl` | INFO |

Windows ACL findings identify broad allow grants for Everyone, Authenticated
Users or Users. They are review prompts, not a complete effective-permissions
calculation. `fix --apply` does not edit Windows ACLs. Saved reports receive a
private ACL before any report content is written; the save fails if that step
cannot complete.

The scanner does not read browser passwords, private-key contents, Windows
Credential Manager, DPAPI secrets, or BitLocker recovery keys. It does not
prove that a listening port is reachable through a firewall or from the
Internet. Windows results should be validated on the target PC before making
security changes.

Microsoft references: [BitLocker status](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide), [firewall profiles](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile), [Defender status](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus), [TCP listeners](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection), [ACLs](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-acl).
