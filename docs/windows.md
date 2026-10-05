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

## Chrome extension metadata

The `browser` scanner counts extension directories for Chrome, Brave and Edge,
but inspects bounded `manifest.json` files only beneath Google Chrome. It
reports aggregate counts for broad website patterns, a fixed list of
high-impact declared permissions, and nonstandard manifest update URLs. It
never reports extension IDs, names, host patterns, URLs or local profile
paths. A missing update URL means the source cannot be determined from that
manifest; it is not treated as a confirmed Chrome Web Store installation.
The scan considers at most 20 profiles, 200 extension directories per profile,
10 stored version directories per extension, and 256,000 bytes per manifest.
It may inspect more than one stored version; findings are review prompts, not
proof that a particular package version is currently active.

The scanner checks only whether the `ExtensionSettings` string value is present
and valid under `HKCU\Software\Policies\Google\Chrome` or
`HKLM\Software\Policies\Google\Chrome`.
It does not inspect cloud policy, other extension policy values, or prove that
policy is effective. Review `chrome://policy` and active extensions in Chrome.
Manifest declarations do not establish which optional permissions were
granted, which stored package version is active, whether an extension is
malicious, or whether its publisher is trusted. No browser database, `Local
State`, `Secure Preferences`, history, cookies or saved credentials are read.
Unreadable, malformed or over-limit metadata is reported as incomplete.

For MFA, passkeys and Windows Hello/PIN, use the [personal manual checklist](manual-security-checklist.ja.md).
These checks cannot be fully certified by a local script.

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
