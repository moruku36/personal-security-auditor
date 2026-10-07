# Manual review and local comparison

## Password Checkup

Run `security-audit password-checkup` for guidance. In Chrome, open
**Passwords and autofill > Google Password Manager > Checkup**.
[Google's instructions](https://support.google.com/chrome/answer/95606?hl=en)
describe the UI flow. Google performs the check; the CLI does not reproduce it,
open authentication databases, export passwords, or start a network request.
The passwords.google.com alternative covers saved Google Account passwords;
local-only passwords must be reviewed in the appropriate Chrome profile.

After reviewing the relevant profiles/accounts, choose an aggregate result:

```sh
security-audit password-checkup --result clear
security-audit password-checkup --result issues --date 2026-10-08
security-audit password-checkup --result unchecked
security-audit password-checkup --forget
```

`clear` means the user reported no issues in the reviewed scope, `issues`
means problems were reported, and `unchecked` means no completed review.
Completed reviews default to today's local date; an explicit date must be a
valid YYYY-MM-DD and cannot be in the future. Unchecked has no date.
The aggregate record is `~/.security-audit/password-checkup.json` and contains
exactly `result` and `checked_on`. No passwords, site names, account names,
profile names, screenshots, raw browser output or problem counts are accepted.
The record is overwritten on a new explicit result; no history is kept.
`--forget` removes that record. Merely asking for guidance or scanning creates
no record. The browser scan adds this review when a Chrome data directory is
detected on macOS/Windows.

A stored review is self-reported and applies only to the date and scope the
user checked. An old clear result does not establish current protection.
Several profiles/accounts are deliberately combined without storing their
identities; rerun the check when that scope changes.

## Effective extension review

```sh
security-audit browser-review Chrome
security-audit browser-review Chrome --result clear --date 2026-10-08
security-audit browser-review Brave --result issues
security-audit browser-review Chrome --forget
```

The browser argument is Chrome, Brave, Edge, Firefox or Safari. The user reviews
enabled extensions, displayed effective permissions/site access and publisher
information in that browser's UI. The CLI stores only the aggregate result
and date at `~/.security-audit/extensions-<browser>.json` with the same
retention and deletion behavior as Password Checkup.
It never accepts extension/site/account identifiers. This is a separate
`user_reported_ui` finding, not verification of manifest declarations.
Manual commands can guide review independently of automatic discovery.

Chrome manifest evidence includes requested and optional permissions and
stored versions. It does not establish active versions, effective grants or
publisher identity. Brave/Edge get directory counts, Firefox/Safari get
presence checks. Run `security-audit coverage` for the matrix.

## Report schema and states

JSON reports have `schema_version: 2`. Existing `overall_risk`, `findings`
and legacy finding fields remain; each finding adds `id`, `category`,
`status`, `evidence_source`, `limitations` and nullable `checked_on`.
The overall risk is a review priority, independent of check completeness.

| State | Meaning |
| --- | --- |
| observed | A metadata/configuration fact was observed; no safety judgment |
| needs_review | The fact needs interpretation or a manual decision |
| pass | A specific check succeeded, or the user reported clear; inspect its evidence source |
| issue | A specific problematic setting/permission or user-reported issue |
| unknown | Not reviewed or insufficient evidence, including conflicting policy values |
| unavailable | Inaccessible, malformed, capped, or unsupported check/record |

Manual missing/unchecked records are unknown. Malformed/inaccessible records
are unavailable and their raw contents/errors are never shown.
Evidence labels separate stored metadata, manifest declarations, configured
policy, local commands, file permissions, manual review and user-reported UI.
Configured policy is not effective browser state.

OS checks now emit successful states too. An individual OS check keeps its
rule code and ID across pass/issue/unavailable states instead of switching to a
generic unavailable code. Consumers that assumed only problems are returned
must filter by status. Legacy JSON remains readable but cannot be used as an
ID/state snapshot; create a new baseline. No automatic migration is performed.

## Opt-in local comparison

```sh
security-audit scan browser --snapshot reports/browser-baseline.json
security-audit report browser --format json --compare reports/browser-baseline.json
security-audit scan browser --compare reports/browser-baseline.json --snapshot reports/browser-baseline.json
```

Comparison output uses stderr so JSON/Markdown stdout remains a valid report.
The last command explicitly replaces the baseline after a successful comparison.
Ordinary scans retain no snapshots. Use different paths for `--output` and
`--snapshot`.

Snapshot schema version 1 contains only schema/identity versions, an opaque
scan-scope digest, and finding ID/state pairs. It excludes titles, recommendations,
paths, extension metadata, risk, counts, review dates and raw output.
IDs are SHA-256 of category/rule/location; scope hashes OS, home/repository
paths, categories and full-scan selection. They are stable comparison keys,
not an anonymization guarantee; keep snapshots private and local.
Duplicate IDs represent an aggregate; unavailable/unknown outrank issue/review/
observed/pass so loss of evidence is not converted to a pass.

The same host/repository path, categories, OS and full-scan mode are required.
Incompatible schemas/identity versions, malformed data and different scopes
are rejected with a generic error. Input is bounded to 1 MB and 5,000 entries.
Missing IDs mean **not observed now**, never automatically resolved.
Incomplete adapters, inaccessible directories or scan bounds may hide a
previous finding. Counts/risk/date changes alone are not compared.
The comparison prints this limitation even when no changes are observed.

Records/snapshots use the existing private atomic writer (0600 on POSIX,
user-only ACL applied before writing on Windows). State/snapshot paths reject
symlinks and Windows reparse points. A permission or comparison failure stops
the operation and preserves an existing baseline. Keep them outside Git or
under ignored `reports/`. Explicit snapshots persist until overwritten or
deleted by the user; there is no background service, upload or scheduling.
