# Security model

- No telemetry, remote APIs, browser credential stores, or keychain reads.
- Assignment scanner collects variable names only. It discards value bytes
  without assembling a line or creating fingerprints.
- Untrusted subprocess stderr is never returned; stdout is reduced to fixed
  status facts before findings are constructed.
- Reports contain findings only. Files are created with mode 0600 and ignored
  by Git. Path labels are restricted to safe characters.
- The app does not claim that absence of findings means the system is safe.
- `fix` changes only permissions, only when `--apply` is explicitly supplied.

## Limitations

The metadata-only scanner cannot detect secrets under unknown variable names,
inside arbitrary files, or in Git history. Browser extension permission and
account MFA checks require manual review. A future optional scanner can use
an offline engine after verifying its output handling and license.
