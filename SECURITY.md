# Security policy

## Supported versions

Security fixes are applied to the latest release.

## Reporting a vulnerability

Do not open a public issue containing a working exploit, a real encryption key,
or a note database. Use the repository host's private vulnerability-reporting
feature. Maintainers should add a dedicated security contact before publishing.

## Design boundaries

CipherNote encrypts selected fields at rest with AES-256-GCM and authenticates
their associated note ID and field name. It does not hide database size, note
count, timestamps, importance, or access patterns. It does not defend against
malware, an administrator, memory inspection, a malicious MCP client, or key
exposure. It is not a password manager.

