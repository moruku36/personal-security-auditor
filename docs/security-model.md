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
have received a point-in-time physical-device run; browser UI review is limited
to the settings and visible context checked manually. This is not a
certification or coverage guarantee. CI exercises behavior with controlled
fixtures and does not inspect its runner's real environment. See the physical-
validation notes in the READMEs for scope and limitations.

## Aggregate manual records and snapshots

- Manual Password Checkup/effective-extension records accept only a fixed
  result and valid local check date. No credential values, account/site names,
  extension identifiers or screenshots are accepted. Missing/unchecked is
  unknown; inaccessible/malformed is unavailable. User-reported clear is not
  independent validation of browser state.
- Records are bounded to 512 bytes; comparison inputs to 1 MB/5,000 entries.
  Inputs have exact allowlisted keys. Raw contents and parse/error text are
  never returned.
- Explicit snapshots contain opaque finding ID/state pairs plus schema,
  identity and scope digests. They exclude raw reports and personal browser
  metadata. Hashes are comparison keys, not an anonymity guarantee.
  Disappearance is not automatic resolution; incompatible scope/schema aborts.
- The existing private atomic writer is reused: Windows ACLs must succeed
  before content is written, and an existing file survives a failed save.
  State/snapshot paths reject redirected ancestors, links and reparse points.
- No snapshot is retained by ordinary scans; no scheduling or network requests
  are added. Manual records overwrite a single local result; `--forget`
  deletes it. Snapshots persist until explicitly replaced/deleted.

See [review and comparison](review-and-comparison.md) for data flow, schema
compatibility, scope, retention and limitations.
