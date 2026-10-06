# Security auditor roadmap

This document describes possible future work, not implemented or enabled
features. Priorities favor clear evidence, predictable contracts and privacy
before broader collection or automation.

## Current baseline

The CLI orchestrates independent scanners through `detect`, `scan` and
`recommendations`. Findings are immutable, and reporting consumes findings
rather than raw command output or file contents. macOS and Windows have selected
OS adapters; Linux coverage is explicitly incomplete. Browser coverage is
uneven: Chrome has bounded manifest and selected Windows policy checks; Brave
and Edge are currently counted for extension directories, while Firefox is
detected for presence. These are different coverage levels, not interchangeable
browser audits. See [Windows checks](windows.md) for detail.

## Priorities

### 1. Stabilize scanner and finding contracts

- Define typed OS and browser adapter inputs/outputs and a versioned report
  schema before adding more platforms or fields.
- Give findings stable identifiers and explicit fields for category, severity,
  status, evidence source, and limitations. Keep `unknown`/`unavailable`
  distinct from `off` or a negative result.
- Evolve schemas additively where possible; document compatibility and report
  migration behavior before changing serialized output.
- Keep scanners replaceable without coupling platform commands to the CLI or
  report renderer.

### 2. Separate evidence types and browser coverage

- Represent stored-package metadata, manifest declarations, configured policy,
  manually observed effective settings, and unavailable evidence as distinct
  evidence types. A declaration must never imply that a permission is granted
  or that a package is active.
- Keep Chrome as the first browser adapter. Expand it only when effective state
  can be read without opening authentication stores or other private profile
  data; otherwise direct users to a manual review.
- Treat Brave and Edge as directory-count coverage, and Firefox as presence
  coverage, until each receives its own documented adapter, privacy review and
  fixture suite. Do not infer parity from shared Chromium ancestry.

### 3. Build a fixture and physical-validation matrix

- Add synthetic fixtures for each supported OS/browser and each known state:
  enabled, disabled, conflicting, malformed, inaccessible and incomplete.
- Make CI test parsers, bounds, redaction and report compatibility using only
  synthetic data. CI runner success is not physical-device validation.
- Maintain a matrix of implementation, fixture and physical validation by OS,
  version and browser. Record only method, scope and limitations; keep host
  findings, account identifiers, profile paths and screenshots private.
- Add a real-device claim only after an actual device run. State the tested
  scope and avoid generalizing one machine or one visible browser context.

### 4. Keep data collection minimal

- For each adapter, document an allowlist of fields and a maximum size/count
  before reading data. Prefer fixed status facts over raw command output.
- Never read passwords, cookies, browser authentication databases, keychain or
  DPAPI secrets, private-key contents, recovery keys, or secret-bearing file
  contents. Do not collect extension names, IDs, site lists, host patterns,
  profile paths or account identifiers unless a separately reviewed feature
  truly requires them.
- Keep reports local and access-restricted. Redact paths and identifiers; fail
  closed if private report permissions cannot be applied. Do not add telemetry,
  uploads or remote API calls as a default.

### 5. Consider local report comparison and optional scheduling

- A local comparison may summarize changes by stable finding ID and state, with
  explicit handling for schema changes and incomplete scans. Do not retain raw
  scanner output or personal browser metadata for comparison.
- Any recurring scan should be opt-in, visible, easy to pause/remove, and run
  with the least privileges needed. Document schedule, local report location,
  retention and deletion behavior before implementation.
- Do not silently install background services, enable monitoring, or send
  results off-device.

### 6. Expand remediation only with reversible safeguards

- Keep preview/dry-run as the default. Before any apply operation, show each
  proposed change and require a separate, explicit user approval for that
  change.
- Apply only a narrow allowlist of supported changes. Create and verify a
  protected backup before mutation; provide a tested rollback path and explain
  cases where rollback is not possible. Abort if backup or preconditions fail.
- Never broaden access, change account authentication, rotate/revoke secrets,
  alter browser extensions, or change OS/network security settings as an
  unattended action. Windows ACL remediation remains out of scope until a safe,
  reversible design is demonstrated.

## Review gates

Each new adapter or automation should include a data-flow review, threat-model
update, synthetic regression fixtures, platform-specific validation notes and
documentation of unknown states. Broader coverage is not a reason to weaken
privacy or turn a review prompt into an unsupported security guarantee.
