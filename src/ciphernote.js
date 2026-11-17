import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

export const SERVER_VERSION = "0.2.0";

const directory = path.dirname(fileURLToPath(import.meta.url));
const store = path.join(directory, "store.py");

function callStore(action, args = {}) {
  const python = process.env.CIPHERNOTE_PYTHON || (process.platform === "win32" ? "python" : "python3");
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
    child.stdin.end(JSON.stringify({ action, args }));
  });
}

function result(value) {
  return { content: [{ type: "text", text: JSON.stringify(value) }] };
}

export function createCipherNoteServer() {
  const server = new McpServer({ name: "ciphernote-mcp", version: SERVER_VERSION });

  server.tool(
    "private_note_write",
    "Write an encrypted local note. Do not use it for passwords, tokens, or other credentials.",
    {
      title: z.string().min(1).max(200),
      content: z.string().min(1).max(100_000),
      tags: z.array(z.string().max(80)).max(20).optional(),
      importance: z.number().int().min(0).max(5).optional(),
    },
    async (args) => result(await callStore("write", args)),
  );

  server.tool(
    "private_note_search",
    "Search encrypted notes locally.",
    { query: z.string().min(1).max(500), limit: z.number().int().min(1).max(20).default(5) },
    async (args) => result(await callStore("search", args)),
  );

  server.tool(
    "private_note_read",
    "Read one encrypted note by ID.",
    { note_id: z.string().min(1).max(128) },
    async (args) => result(await callStore("read", args)),
  );

  server.tool(
    "private_note_recent",
    "List recent note metadata without returning note bodies.",
    { limit: z.number().int().min(1).max(20).default(5) },
    async (args) => result(await callStore("recent", args)),
  );

  server.tool(
    "private_note_delete",
    "Permanently delete one note by ID.",
    { note_id: z.string().min(1).max(128) },
    async (args) => result(await callStore("delete", args)),
  );

  return server;
}
