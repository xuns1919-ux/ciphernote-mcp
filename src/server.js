#!/usr/bin/env node

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createCipherNoteServer } from "./ciphernote.js";
import { listenHttpService, loadHttpConfig } from "./http.js";

const mode = (process.env.CIPHERNOTE_TRANSPORT || "stdio").trim().toLowerCase();

if (mode === "stdio") {
  const server = createCipherNoteServer();
  await server.connect(new StdioServerTransport());
} else if (mode === "http") {
  const service = await listenHttpService(loadHttpConfig(), createCipherNoteServer);
  const shutdown = () => {
    service.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
} else {
  throw new Error("CIPHERNOTE_TRANSPORT must be stdio or http");
}
