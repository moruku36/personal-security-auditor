# Threat model

Assets: local credentials, browser sessions, SSH keys, cloud accounts, reports.
Adversaries: another local user, malicious repository content, an exposed
service, or a compromised extension. Trust boundary: local filesystem and
subprocess output are untrusted. The CLI must not relay them verbatim to
terminal, reports, CI, or a remote service.

Residual risks: a same-user malicious process can read process memory; metadata
alone misses many real leaks; port binding does not prove Internet exposure;
directory permissions do not describe all agent tool permissions. Findings are
triage signals, not proof of compromise or compliance.

## Manual review and comparison data flow

The user runs Google's Password Checkup or reviews effective extensions in the
browser UI. Only a fixed aggregate result and local date enter the CLI. The CLI
writes its own bounded local record with private permissions; scans read that
record rather than browser authentication/profile settings databases.
A manual result is an assertion, not independent evidence that an account,
extension, profile or device is secure. A same-user process can forge or alter
records; dates and evidence labels must remain visible.

Explicit comparison reduces findings to opaque IDs/states and an opaque scope
digest. Snapshot inputs are untrusted: exact key allowlists, state enums,
schema/identity versions, matching scope, regular-file checks, byte/count bounds
and redirected-path rejection prevent arbitrary content from becoming report
text. Atomic private writes preserve an old baseline when snapshot protection
fails. No automatic retention, scheduling, telemetry or upload is introduced.

Residual comparison risks: hashed IDs/scope are not anonymization; stable
metadata may be guessed, duplicate rule/location facts are aggregated, and
count/risk/date changes are omitted. Bounded/incomplete scans can hide prior
facts, so a missing ID is reported as not observed rather than resolved.
Historic UI/device checks do not validate these new features.
