## 0.3.0 - Universal Privacy Mode

- Add standard, private, and strict server-side privacy modes.
- Add encrypted short-lived Secure Capture drafts and one-time MCP commit references.
- Minimize private/strict search and recent results; require authorization for private reads and deletes.

# Changelog

## 0.2.0

- Add native MCP Streamable HTTP transport while keeping stdio as the default.
- Require Bearer authentication for every MCP HTTP request.
- Add optional direct TLS with TLS 1.2 as the minimum version.
- Add allowed-Host validation and fail-closed rules for non-loopback listeners.
- Add configurable request-body limits and a minimal `/healthz` endpoint.
- Add stdio, HTTP authentication, TLS, `initialize`, and `tools/list` tests.
- Upgrade Zod to a release without GHSA-mrhx-c7xc-m3w5 and commit the npm lockfile.

## 0.1.0

- Initial local stdio release with encrypted SQLite note storage.
