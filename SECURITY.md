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


## Universal Privacy Mode threat model (v0.3.0)

Database encryption at rest does not hide plaintext already sent as MCP tool arguments or results. A client can display, copy, retain, synchronize, or forward those values to a model. standard intentionally preserves this compatibility behavior.

private and strict enforce server-side minimization:

- private search returns only count and note IDs; recent hides title/tags; read and delete require the authenticated Secure Capture path; direct write is not registered by default.
- strict search returns count only; recent returns only IDs; ordinary MCP never returns full note content.
- private_note_commit_draft accepts only a short-lived opaque draft ID. The encrypted draft is bound to the hash of the authenticated deployment token and a browser session, consumed once, and removed after commit.
- Secure Capture checks Host/Origin, uses Bearer login plus HttpOnly/SameSite cookies, no localStorage, bounded request bodies, and no request-body logging.

This is deployment-level authorization, not per-human identity isolation. A shared Bearer token is a shared authority. Do not trust a model-supplied user_id or boolean as an authorization proof.

The secure page is an authenticated content path; its authorized browser can see plaintext by design. No standard MCP server can force every client UI to hide parameters that the client has already received. Client-by-client UI/history validation remains NOT_VERIFIED unless actually performed.

Production guidance:

- bind the Node service to loopback behind an HTTPS reverse proxy;
- preserve Authorization for /mcp, do not log request bodies, and protect /notes/capture;
- keep CIPHERNOTE_KEY and the Bearer token in separate protected files;
- back up the encrypted database and key separately;
- rollback v0.3.0 by stopping the service, restoring the previous source and environment, and retaining the database (the new secure_drafts table is additive and ignored by v0.2.0).


### Cross-transport subject

CIPHERNOTE_SUBJECT_ID is an optional stable random deployment subject for a single-user instance. Without it, HTTP uses a hash of the Bearer token and stdio uses stdio, so drafts cannot cross transports. With it, only the already-authenticated HTTP Bearer path and the trusted local stdio process share the same deployment authority. This does not create per-user isolation; use separate instances or an identity-aware proxy for multiple people.


Secure Capture compares the complete Origin scheme, hostname, and effective port. Cookie-bearing modification requests require Origin; missing or mismatched Origin is rejected. CIPHERNOTE_TRUST_PROXY=true is only for a trusted TLS-terminating reverse proxy on a restricted backend; otherwise forwarded protocol headers are ignored.
