# Security model

- No telemetry, remote APIs, browser credential stores, or keychain reads.
- The `api` scanner checks only selected configuration file presence and
  permissions. It never opens those files. It inspects environment variable
  names only; their values are never accessed.
- Untrusted subprocess stderr is never returned; stdout is reduced to fixed
  status facts before findings are constructed.
- Reports contain findings only. Files are created with mode 0600 on POSIX;
  Windows report ACLs are restricted before content is written. Reports are
  ignored by Git. Path labels are restricted to safe characters.
- Windows credential ACLs are read-only checks for broad grants to Everyone,
  Authenticated Users or Users. Unknown ACL states are reported as incomplete.
- Windows OS and network probes use fixed, local PowerShell commands. Raw
  command output and IP addresses are never emitted in reports.
- Browser checks read only bounded extension `manifest.json` metadata and fixed
  Chrome policy registry values (`ExtensionSettings` presence and
  `SafeBrowsingProtectionLevel` on Windows). They never open browser databases,
  `Local State`, `Secure Preferences`, history, cookies or saved credentials.
  Reports use aggregate fixed-vocabulary findings without extension IDs,
  names, host patterns, update URLs or profile paths.
- The app does not claim that absence of findings means the system is safe.
- Firewall status is marked unavailable inside a known Codex sandbox because
  the macOS status command can return a misleading value there.
- `fix` changes only POSIX permissions, only when `--apply` is explicitly
  supplied. Windows ACLs are never changed by `fix`.

## Limitations

The metadata-only scanner cannot detect secrets inside arbitrary files or in
Git history. Manifest declarations do not prove effective extension grants,
the active version, publisher trust or update status. Account MFA, passkeys and
Windows Hello/PIN checks require manual review. See the personal checklist.
Safe Browsing registry values do not prove the effective browser setting or
include cloud policy/user preferences. Chrome user settings, account MFA,
passkeys and Windows Hello/PIN checks require manual review. Windows checks
have not yet been validated on a personal Windows machine; CI exercises their
behavior with controlled fixtures.
