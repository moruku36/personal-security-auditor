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
