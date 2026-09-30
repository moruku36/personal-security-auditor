# Security model

- No telemetry, remote APIs, browser credential stores, or keychain reads.
- Assignment scanner collects variable names only. It discards value bytes
  without assembling a line or creating fingerprints.
- Untrusted subprocess stderr is never returned; stdout is reduced to fixed
  status facts before findings are constructed.
- Reports contain findings only. Files are created with mode 0600 on POSIX;
  Windows report ACLs are restricted before content is written. Reports are
  ignored by Git. Path labels are restricted to safe characters.
- Windows credential ACLs are read-only checks for broad grants to Everyone,
  Authenticated Users or Users. Unknown ACL states are reported as incomplete.
- Windows OS and network probes use fixed, local PowerShell commands. Raw
  command output and IP addresses are never emitted in reports.
- The app does not claim that absence of findings means the system is safe.
- Firewall status is marked unavailable inside a known Codex sandbox because
  the macOS status command can return a misleading value there.
- `fix` changes only POSIX permissions, only when `--apply` is explicitly
  supplied. Windows ACLs are never changed by `fix`.

## Limitations

The metadata-only scanner cannot detect secrets under unknown variable names,
inside arbitrary files, or in Git history. Browser extension permission and
account MFA checks require manual review. A future optional scanner can use
an offline engine after verifying its output handling and license.
Windows checks have not yet been validated on a personal Windows machine;
CI exercises their behavior with controlled fixtures.
