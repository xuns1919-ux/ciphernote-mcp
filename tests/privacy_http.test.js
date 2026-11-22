import assert from "node:assert/strict";
import test from "node:test";
import { once } from "node:events";
import { createCipherNoteServer } from "../src/ciphernote.js";
import { createCipherNoteHttpService } from "../src/http.js";

const TOKEN = "0123456789abcdef0123456789abcdef";

function headers(token = TOKEN) {
  return { authorization: `Bearer ${token}`, accept: "application/json, text/event-stream", "content-type": "application/json" };
}

test("private secure capture keeps plaintext out of MCP draft parameters", async (t) => {
  const previous = { key: process.env.CIPHERNOTE_KEY, db: process.env.CIPHERNOTE_DB, mode: process.env.CIPHERNOTE_PRIVACY_MODE };
  process.env.CIPHERNOTE_KEY = "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  process.env.CIPHERNOTE_DB = `${process.env.TEMP || process.env.TMPDIR}/ciphernote-privacy-http-${Date.now()}.db`;
  process.env.CIPHERNOTE_PRIVACY_MODE = "private";
  const config = {
    host: "127.0.0.1", port: 0, path: "/mcp", token: TOKEN, allowedHosts: new Set(["127.0.0.1"]),
    maxBodyBytes: 1024 * 1024, privacyMode: "private", secureCaptureEnabled: true, tls: undefined,
  };
  const service = createCipherNoteHttpService(config, createCipherNoteServer);
  service.listen(0, "127.0.0.1");
  await once(service, "listening");
  const base = `http://127.0.0.1:${service.address().port}`;
  t.after(async () => {
    await new Promise((resolve) => service.close(resolve));
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  });

  const loginPage = await fetch(`${base}/notes/capture`);
  assert.equal(loginPage.status, 200);
  assert.match(await loginPage.text(), /Secure Capture/);
  const login = await fetch(`${base}/notes/capture/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token: TOKEN }) });
  assert.equal(login.status, 200);
  assert.match(login.headers.get("set-cookie"), /HttpOnly/);
  const missingSession = await fetch(`${base}/notes/capture/save`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ title: "x", content: "y" }) });
  assert.equal(missingSession.status, 401);
  const csrf = await fetch(`${base}/notes/capture/drafts`, { method: "POST", headers: { origin: "https://evil.example", "content-type": "application/json" }, body: JSON.stringify({ title: "x", content: "y" }) });
  assert.equal(csrf.status, 403);
  const cookie = login.headers.get("set-cookie").split(";", 1)[0];
  const draftResponse = await fetch(`${base}/notes/capture/drafts`, {
    method: "POST", headers: { cookie, "content-type": "application/json" },
    body: JSON.stringify({ title: "隐藏标题", content: "隐藏正文", tags: ["隐藏标签"], importance: 1 }),
  });
  const draft = await draftResponse.json();
  assert.equal(draft.success, true);
  assert.ok(draft.draft_id.startsWith("draft_"));
  assert.equal(JSON.stringify(draft).includes("隐藏正文"), false);

  const savedResponse = await fetch(`${base}/notes/capture/save`, { method: "POST", headers: { cookie, "content-type": "application/json" }, body: JSON.stringify({ title: "页面标题", content: "页面正文", tags: ["页面标签"], importance: 2 }) });
  const saved = await savedResponse.json();
  assert.equal(saved.success, true);
  const readResponse = await fetch(`${base}/notes/capture/read`, { method: "POST", headers: { cookie, "content-type": "application/json" }, body: JSON.stringify({ note_id: saved.note_id }) });
  const read = await readResponse.json();
  assert.equal(read.content, "页面正文");
  const deleteResponse = await fetch(`${base}/notes/capture/delete`, { method: "POST", headers: { cookie, "content-type": "application/json" }, body: JSON.stringify({ note_id: saved.note_id }) });
  assert.equal((await deleteResponse.json()).success, true);
  const initialize = await fetch(`${base}/mcp`, { method: "POST", headers: headers(), body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }) });
  assert.equal(initialize.status, 200);
  const commit = await fetch(`${base}/mcp`, {
    method: "POST", headers: headers(), body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "private_note_commit_draft", arguments: { draft_id: draft.draft_id } } }),
  });
  const committed = await commit.text();
  assert.equal(commit.status, 200);
  assert.equal(committed.includes("隐藏正文"), false);
  assert.match(committed, /note_id/);
});
