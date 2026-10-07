# Personal Security Auditor

[English](README.md) | [日本語](README.ja.md)

## Overview

A local-first CLI for **defensive security review of your own macOS or Windows
workstation**. It flags selected OS hardening states, credential-file permissions,
Chrome extension manifest declarations, and non-loopback TCP listeners, then
produces local findings and recommendations.

It does not collect password, token, or private-key values. **Google Password
Checkup is not implemented**; saved-password checks, account protection, and
browser-effective permissions require separate manual review. A clean report
is not proof that a device is secure.

Automated tests use synthetic fixtures. The [physical validation](#physical-validation)
notes describe point-in-time checks on one Mac and one Windows PC; they do not
establish coverage or compatibility for every device. See the
[security model](docs/security-model.md) for data boundaries and limitations.

## Why

Help workstation owners prioritize configuration and permission issues for
manual review, while keeping sensitive values and host-specific reports local.

## Features

- macOS FileVault, firewall, Gatekeeper, SIP and Remote Login checks
- Windows drive encryption, active firewall, Defender, UAC and Secure Boot checks
- Browser presence, bounded Chrome extension manifest metadata and permission review flags, and Windows Safe Browsing policy checks
- Candidate `.env` and shell configuration file presence and permission metadata; file contents are not read
- Git repository hygiene, SSH and cloud credential file permissions
- Developer CLI presence and credential-store file permissions
- Non-loopback TCP listeners on macOS and Windows, and AI agent directory permissions
- Terminal, Markdown and JSON reports; conservative permission fix preview

## Architecture

Independent scanner objects implement `detect`, `scan`, and `recommendations`.
They return fixed-vocabulary findings to a shared risk and report layer.
See [architecture](docs/architecture.md), [security model](docs/security-model.md),
and [threat model](docs/threat-model.md).

## Installation

Python 3.11+ is required. No runtime dependencies or network access are needed.

```sh
python3 -m pip install -e .
```

On Windows, use `py -3.11 -m pip install -e .` in PowerShell. Run the CLI on
native Windows, not WSL, to use Windows security checks. Administrator rights
are not required for a basic scan; Secure Boot or some other statuses may be
reported unavailable without them.

## Quick Start

```sh
security-audit scan
security-audit scan --full
security-audit scan api
security-audit report --format markdown --output reports/latest.md
security-audit report --format json --output reports/latest.json
security-audit fix             # preview only
security-audit fix --apply     # permission changes shown by preview
```

`--repository PATH` selects the repository to inspect. `--full` adds a bounded
search of direct repositories under `~/Documents` and `~/Developer`.

## Security Model

Secret values, browser credential stores and private keys are never requested
or included in findings. The `api` scanner checks selected configuration file
presence and permissions without opening file contents. Browser checks read
bounded extension manifests only; they do not inspect Chrome databases or
settings files. Reports use mode 0600 on macOS and a restricted ACL on Windows,
and are ignored by Git.
The CLI has no telemetry, cloud upload or remote API calls. Findings may be
incomplete; a clean report is not a security certification.

## Privacy

Telemetry: off. Cloud upload: off. Remote API: off. Secret collection: off.
Commands run locally. CI tests use fake credentials only and never audit the
runner's real environment.

## Supported Platforms

macOS and Windows 10/11 are supported. Windows checks use built-in Windows
PowerShell and local APIs. Linux reports OS and network coverage as incomplete.
Neither platform sends scan data to a remote service.
See [Windows checks and limits](docs/windows.md) before interpreting results.

## Scanners

| Category | Current coverage |
| --- | --- |
| `os` | Selected macOS and Windows hardening states |
| `browser` | Browser directories, bounded Chrome manifest metadata, and Windows policy presence |
| `api` | Candidate configuration file presence and permissions; no file content |
| `git` | `.gitignore` presence and history scan reminder |
| `ssh` | Directory and key permissions or Windows ACL review |
| `cloud` | CLI presence and credential file permissions or Windows ACL review |
| `dev` | Developer CLI presence and local credential file permissions or Windows ACL review |
| `network` | Non-loopback TCP listeners on macOS and Windows |
| `ai` | Agent directory presence and permissions |

Effective extension grants, extension publisher identity, browser update status,
Chrome user preferences, MFA, passkeys, Windows Hello PIN safety, cloud IAM and
Git history leak detection require separate manual review. See the [personal
checklist](docs/manual-security-checklist.ja.md).
External credential validation is intentionally absent.

## Risk Levels

`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` in descending order. A non-loopback
listener is marked HIGH for review, but binding alone does not prove Internet
exposure.

## Remediation

On macOS, `fix` previews permission changes and `fix --apply` tightens only
selected file or directory permissions. On Windows, ACL findings are read-only;
`fix` does not change them. The tool does not revoke credentials, change IAM or
MFA, delete files, or remove extensions. Review each proposed change before
applying it.

## Physical validation

On 2026-10-06, the macOS scan and permission-fix flow completed on one physical Mac running macOS 27.2 with Python 3.11.4, using auditor source commit `20332630d64626a421b5508244cc002bdd64eb44`. A follow-up scan completed successfully. Host-specific findings and the report remain local and are not published here.

On 2026-10-06, the CLI's OS and browser scans also completed on one physical Windows PC, and creation of a report with a user-only ACL was confirmed. A manual browser UI review checked the visible protection state and reviewed enabled extensions' displayed permissions/site access against publisher and store/developer information supplied for verification. An AI-service UI review covered its approved-site list and the scope shown for the conversation on screen. Host-specific findings, extension and site names, account identifiers, screenshots and reports are not published here.

These are point-in-time execution and UI checks on individual hosts and visible contexts. They are not a security certification, a guarantee for other machines or sessions, proof of absence of malicious code, or a compatibility guarantee. The CLI's Chrome manifest scan reports declarations and stored metadata; it does not independently establish effective grants or publisher identity. CI uses synthetic fixtures and does not audit the runner's real environment or replace physical-device validation. Some checks may be unavailable depending on host permissions or sandboxing.

## Roadmap

See the [security auditor roadmap](docs/roadmap.md) for prioritized extension plans and their safety boundaries. These items are proposals, not implemented or enabled features.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Never include real credentials in tests,
issues, logs, or pull requests.

## License

MIT. See [LICENSE](LICENSE).
