# Personal Security Auditor

[English](README.md) | [日本語](README.ja.md)

## Overview

A local-first CLI for reviewing personal computer security without collecting
secret values. It produces actionable findings from metadata and selected OS
status checks.

## Why

Credentials and agent permissions are scattered across a developer workstation.
This project provides a safe first pass before deeper manual review.

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

## Roadmap

- Validate macOS and Windows checks on physical machines and add a Linux adapter
- Expand read-only Chrome checks only where settings can be collected without reading private profile data
- Evaluate an opt-in offline Git history scanner
- Add optional update checks

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Never include real credentials in tests,
issues, logs, or pull requests.

## License

MIT. See [LICENSE](LICENSE).
