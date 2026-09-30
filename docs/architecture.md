# Architecture

The CLI orchestrates independent scanners through `detect`, `scan`, and
`recommendations`. Scanners return immutable findings. Reporting accepts only
findings, never raw command output or file content. Every command is local.

The macOS adapter currently covers selected OS and network checks. Other
platforms return an explicit incomplete finding. Category scanners can be
replaced without changing reporting. `fix` is a separate path and defaults
to a preview.

The first release intentionally uses Python's standard library. Third-party
dependencies and remote update checks are deferred until their data flow can
be audited.
