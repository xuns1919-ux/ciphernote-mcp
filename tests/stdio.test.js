import assert from "node:assert/strict";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

test("stdio remains the default transport", async () => {
  const client = new Client({ name: "ciphernote-stdio-test", version: "1.0.0" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ["src/server.js"],
    env: { ...process.env, CIPHERNOTE_TRANSPORT: "stdio" },
    stderr: "pipe",
  });

  try {
    await client.connect(transport);
    const result = await client.listTools();
    assert.deepEqual(
      result.tools.map((tool) => tool.name).sort(),
      [
        "private_note_delete",
        "private_note_read",
        "private_note_recent",
        "private_note_search",
        "private_note_write",
      ],
    );
  } finally {
    await client.close();
  }
});
