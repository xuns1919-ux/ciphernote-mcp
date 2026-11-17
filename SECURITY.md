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

## Remote transport

Native Streamable HTTP mode fails closed:

- A Bearer token of at least 32 characters is mandatory.
- Token comparison uses a timing-safe comparison.
- Non-loopback listeners require TLS and an explicit allowed-host list.
- TLS certificate and key settings must be provided together.
- Request bodies default to a 1 MiB limit and cannot be configured above 10 MiB.
- Authentication tokens, encryption keys, and note contents are never written to
  application logs.

For reverse-proxy deployments, bind CipherNote to `127.0.0.1`, terminate TLS at
the proxy, preserve the `Authorization` header, and expose only the HTTPS proxy
port. Direct TLS mode requires `CIPHERNOTE_TLS_CERT` and
`CIPHERNOTE_TLS_KEY` and enforces TLS 1.2 or newer.

Bearer authentication controls access to the MCP endpoint; it does not provide
per-tool or per-note authorization. Any client holding the token can call every
tool, including write and permanent delete. Use a dedicated deployment and token
when clients should not share the same authority.
