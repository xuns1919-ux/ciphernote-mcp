import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

export const SERVER_VERSION = "0.3.0";

const directory = path.dirname(fileURLToPath(import.meta.url));
const store = path.join(directory, "store.py");

function privacyMode() {
  const mode = (process.env.CIPHERNOTE_PRIVACY_MODE || "standard").trim().toLowerCase();
  if (!["standard", "private", "strict"].includes(mode)) {
    throw new Error("CIPHERNOTE_PRIVACY_MODE must be standard, private, or strict");
  }
  return mode;
}

export function callStore(action, args = {}, subject = "stdio") {
  const python = process.env.CIPHERNOTE_PYTHON || (process.platform === "win32" ? "python" : "python3");
  const safeArgs = { ...args, _subject: subject };
  return new Promise((resolve) => {
    const child = execFile(
      python,
      [store],
      { env: process.env, timeout: 15_000, windowsHide: true },
      (error, stdout) => {
        if (error) return resolve({ success: false, reason: "notebook_unavailable" });
        try {
          resolve(JSON.parse(stdout));
        } catch {
          resolve({ success: false, reason: "invalid_notebook_response" });
        }
      },
    );
    child.stdin.end(JSON.stringify({ action, args: safeArgs }));
  });
}

function result(value) {
  return { content: [{ type: "text", text: JSON.stringify(value) }] };
}

function registerCommonTools(server, subject) {
  server.tool(
    "private_note_search",
    "Search locally. In private/strict modes, results are intentionally metadata-minimized.",
    { query: z.string().min(1).max(500), limit: z.number().int().min(1).max(20).default(5) },
    async (args) => result(await callStore("search", args, subject)),
  );

  server.tool(
    "private_note_read",
    "Read one note. Private and strict modes require the separate authenticated capture page.",
    { note_id: z.string().min(1).max(128) },
    async (args) => result(await callStore("read", args, subject)),
  );

  server.tool(
    "private_note_recent",
    "List recent note metadata subject to the configured privacy mode.",
    { limit: z.number().int().min(1).max(20).default(5) },
    async (args) => result(await callStore("recent", args, subject)),
  );

  server.tool(
    "private_note_delete",
    "Delete one note. Private and strict modes require the authenticated secure page.",
    { note_id: z.string().min(1).max(128) },
    async (args) => result(await callStore("delete", args, subject)),
  );

  if (privacyMode() !== "standard") {
    server.tool(
      "private_note_commit_draft",
      "Commit a short-lived draft created through the authenticated secure capture page. The draft_id contains no note plaintext.",
      { draft_id: z.string().regex(/^draft_[A-Za-z0-9_-]{20,}$/) },
      async (args) => result(await callStore("commit_draft", args, subject)),
    );
  }
}

export function createCipherNoteServer({ subject = "stdio" } = {}) {
  const mode = privacyMode();
  const server = new McpServer({ name: "ciphernote-mcp", version: SERVER_VERSION });

  const directWriteEnabled = mode === "standard" || process.env.CIPHERNOTE_DIRECT_WRITE_ENABLED === "true";
  if (directWriteEnabled) {
    server.tool(
      "private_note_write",
      mode === "standard"
        ? "Write an encrypted local note."
        : "Compatibility escape hatch: direct plaintext parameters may be visible to MCP clients and chat history.",
      {
        title: z.string().min(1).max(200),
        content: z.string().min(1).max(100_000),
        tags: z.array(z.string().max(80)).max(20).optional(),
        importance: z.number().int().min(0).max(5).optional(),
      },
      async (args) => result(await callStore("write", args, subject)),
    );
  }

  registerCommonTools(server, subject);
  return server;
}
