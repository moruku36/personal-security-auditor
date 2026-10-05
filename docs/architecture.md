# Architecture

The CLI orchestrates independent scanners through `detect`, `scan`, and
`recommendations`. Scanners return immutable findings. Reporting accepts only
findings, never raw command output or file content. Every command is local.

The macOS and Windows adapters cover selected OS and network checks. Windows
uses fixed PowerShell commands whose output is reduced to bounded status facts.
Linux returns an explicit incomplete finding. Category scanners can be
replaced without changing reporting. `fix` is a separate path and defaults
to a preview.

The first release intentionally uses Python's standard library. Third-party
dependencies and remote update checks are deferred until their data flow can
be audited.
