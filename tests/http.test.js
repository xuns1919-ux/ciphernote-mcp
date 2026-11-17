import assert from "node:assert/strict";
import { once } from "node:events";
import test from "node:test";
import { createCipherNoteServer, SERVER_VERSION } from "../src/ciphernote.js";
import {
  createCipherNoteHttpService,
  hasValidBearer,
  loadHttpConfig,
} from "../src/http.js";

const TOKEN = "0123456789abcdef0123456789abcdef";

function config(overrides = {}) {
  return {
    host: "127.0.0.1",
    port: 0,
    path: "/mcp",
    token: TOKEN,
    allowedHosts: new Set(["127.0.0.1"]),
    maxBodyBytes: 1024 * 1024,
    tls: undefined,
    ...overrides,
  };
}

async function startService(overrides = {}) {
  const service = createCipherNoteHttpService(config(overrides), createCipherNoteServer);
  service.listen(0, "127.0.0.1");
  await once(service, "listening");
  const { port } = service.address();
  return {
    service,
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise((resolve) => service.close(resolve)),
  };
}

function mcpHeaders(token = TOKEN) {
  return {
    authorization: `Bearer ${token}`,
    accept: "application/json, text/event-stream",
    "content-type": "application/json",
  };
}

test("Bearer comparison is strict", () => {
  assert.equal(hasValidBearer(`Bearer ${TOKEN}`, TOKEN), true);
  assert.equal(hasValidBearer(`bearer ${TOKEN}`, TOKEN), false);
  assert.equal(hasValidBearer("Bearer wrong", TOKEN), false);
  assert.equal(hasValidBearer(undefined, TOKEN), false);
});

test("HTTP configuration fails closed", () => {
  assert.throws(() => loadHttpConfig({}), /Bearer token/);
  assert.throws(
    () => loadHttpConfig({ CIPHERNOTE_AUTH_TOKEN: `${TOKEN} invalid` }),
    /whitespace-free/,
  );
  assert.throws(
    () => loadHttpConfig({ CIPHERNOTE_AUTH_TOKEN: TOKEN, CIPHERNOTE_HOST: "0.0.0.0" }),
    /requires TLS/,
  );
  assert.throws(
    () => loadHttpConfig({ CIPHERNOTE_AUTH_TOKEN: TOKEN, CIPHERNOTE_TLS_CERT: "cert.pem" }),
    /must be set together/,
  );
});

test("health check works and MCP endpoint requires a valid Bearer token", async (t) => {
  const app = await startService();
  t.after(app.close);

  const health = await fetch(`${app.url}/healthz`);
  assert.equal(health.status, 200);
  assert.deepEqual(await health.json(), { status: "ok" });

  const missing = await fetch(`${app.url}/mcp`, { method: "POST" });
  assert.equal(missing.status, 401);
  assert.equal(missing.headers.get("www-authenticate"), "Bearer");

  const wrong = await fetch(`${app.url}/mcp`, {
    method: "POST",
    headers: mcpHeaders("wrong-token"),
    body: "{}",
  });
  assert.equal(wrong.status, 401);
});

test("Host validation rejects untrusted hosts", async (t) => {
  const app = await startService({ allowedHosts: new Set(["notes.example.com"]) });
  t.after(app.close);
  const response = await fetch(`${app.url}/healthz`);
  assert.equal(response.status, 421);
});

test("Streamable HTTP initialize succeeds with authentication", async (t) => {
  const app = await startService();
  t.after(app.close);

  const response = await fetch(`${app.url}/mcp`, {
    method: "POST",
    headers: mcpHeaders(),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "ciphernote-test", version: "1.0.0" },
      },
    }),
  });

  assert.equal(response.status, 200);
  const body = await response.text();
  assert.match(body, /ciphernote-mcp/);
  assert.match(body, new RegExp(SERVER_VERSION.replaceAll(".", "\\.")));

  const toolsResponse = await fetch(`${app.url}/mcp`, {
    method: "POST",
    headers: { ...mcpHeaders(), "mcp-protocol-version": "2025-06-18" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }),
  });
  assert.equal(toolsResponse.status, 200);
  const toolsBody = await toolsResponse.text();
  for (const name of [
    "private_note_write",
    "private_note_search",
    "private_note_read",
    "private_note_recent",
    "private_note_delete",
  ]) {
    assert.match(toolsBody, new RegExp(name));
  }
});
