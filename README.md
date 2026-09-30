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
- Browser presence and extension directory counts
- Secret-like assignment name discovery in selected shell and `.env` files
- Git repository hygiene, SSH and cloud credential file permissions
- Developer CLI presence and credential-store file permissions
- Non-loopback TCP listeners and AI agent directory permissions
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
or included in findings. The assignment scanner discards value bytes without
assembling them. Reports are owner-only files (0600) and ignored by Git.
The CLI has no telemetry, cloud upload or remote API calls. Findings may be
incomplete; a clean report is not a security certification.

## Privacy

Telemetry: off. Cloud upload: off. Remote API: off. Secret collection: off.
Commands run locally. CI tests use fake credentials only and never audit the
runner's real environment.

## Supported Platforms

macOS is the current primary platform. Windows and Linux can be added through
scanner adapters; their OS and network checks currently report incomplete.

## Scanners

| Category | Current coverage |
| --- | --- |
| `os` | Selected macOS hardening states |
| `browser` | Browser directories and Chromium extension counts |
| `api` | Secret-like assignment names and file permissions |
| `git` | `.gitignore` presence and history scan reminder |
| `ssh` | Directory and key permissions |
| `cloud` | CLI presence and credential file permissions |
| `dev` | Developer CLI presence and local credential file permissions |
| `network` | Non-loopback TCP listeners on macOS |
| `ai` | Agent directory presence and permissions |

Browser version, extension permission, MFA, cloud IAM and Git history leak
detection require a separate manual or opt-in review. External credential
validation is intentionally absent.

## Risk Levels

`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` in descending order. A non-loopback
listener is marked HIGH for review, but binding alone does not prove Internet
exposure.

## Remediation

`fix` previews changes. `fix --apply` only tightens selected file or directory
permissions. It does not revoke credentials, change IAM or MFA, delete files,
or remove extensions. Review each proposed change before applying it.

## Roadmap

- Validate macOS checks on more versions and add Windows/Linux adapters
- Add safe extension metadata and agent permission checks
- Evaluate an opt-in offline Git history scanner
- Add user-led MFA/passkey checklist and optional update checks

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Never include real credentials in tests,
issues, logs, or pull requests.

## License

MIT. See [LICENSE](LICENSE).
