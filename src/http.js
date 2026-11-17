import { timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { isIP } from "node:net";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;

function isLoopback(host) {
  const value = host.toLowerCase();
  return value === "localhost" || value === "127.0.0.1" || value === "::1";
}

function parsePort(value) {
  const port = Number(value ?? 18060);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error("CIPHERNOTE_PORT must be an integer between 0 and 65535");
  }
  return port;
}

function readSecretFile(filename, label) {
  try {
    return readFileSync(filename, "utf8").trim();
  } catch {
    throw new Error(`${label} could not be read`);
  }
}

function loadToken(env) {
  if (env.CIPHERNOTE_AUTH_TOKEN && env.CIPHERNOTE_AUTH_TOKEN_FILE) {
    throw new Error("set only one of CIPHERNOTE_AUTH_TOKEN or CIPHERNOTE_AUTH_TOKEN_FILE");
  }
  const token = env.CIPHERNOTE_AUTH_TOKEN_FILE
    ? readSecretFile(env.CIPHERNOTE_AUTH_TOKEN_FILE, "CIPHERNOTE_AUTH_TOKEN_FILE")
    : env.CIPHERNOTE_AUTH_TOKEN?.trim();
  if (!token || token.length < 32 || /\s/.test(token)) {
    throw new Error("HTTP mode requires a whitespace-free Bearer token of at least 32 characters");
  }
  return token;
}

function normalizeHostname(value) {
  let hostname = value.trim().toLowerCase();
  if (hostname.startsWith("[")) {
    const end = hostname.indexOf("]");
    if (end === -1) return "";
    hostname = hostname.slice(1, end);
  } else if (hostname.includes(":")) {
    if (isIP(hostname) !== 6) hostname = hostname.split(":", 1)[0];
  }
  return hostname.endsWith(".") ? hostname.slice(0, -1) : hostname;
}

function parseAllowedHosts(value, bindHost) {
  const configured = value?.split(",").map(normalizeHostname).filter(Boolean);
  if (configured?.length) {
    const allowed = new Set(configured);
    if (isLoopback(bindHost)) {
      allowed.add("localhost");
      allowed.add("127.0.0.1");
      allowed.add("::1");
    }
    return allowed;
  }
  if (!isLoopback(bindHost)) {
    throw new Error("non-loopback HTTP mode requires CIPHERNOTE_ALLOWED_HOSTS");
  }
  return new Set(["localhost", "127.0.0.1", "::1"]);
}

export function loadHttpConfig(env = process.env) {
  const host = env.CIPHERNOTE_HOST?.trim() || "127.0.0.1";
  const path = env.CIPHERNOTE_HTTP_PATH?.trim() || "/mcp";
  if (!path.startsWith("/") || path.includes("?") || path === "/healthz") {
    throw new Error("CIPHERNOTE_HTTP_PATH must be an absolute path other than /healthz");
  }

  const certFile = env.CIPHERNOTE_TLS_CERT?.trim();
  const keyFile = env.CIPHERNOTE_TLS_KEY?.trim();
  if (Boolean(certFile) !== Boolean(keyFile)) {
    throw new Error("CIPHERNOTE_TLS_CERT and CIPHERNOTE_TLS_KEY must be set together");
  }
  if (!isLoopback(host) && !certFile) {
    throw new Error("non-loopback HTTP mode requires TLS; use a loopback bind behind a TLS proxy");
  }

  const maxBodyBytes = Number(env.CIPHERNOTE_MAX_BODY_BYTES || DEFAULT_MAX_BODY_BYTES);
  if (!Number.isInteger(maxBodyBytes) || maxBodyBytes < 1024 || maxBodyBytes > 10 * 1024 * 1024) {
    throw new Error("CIPHERNOTE_MAX_BODY_BYTES must be between 1024 and 10485760");
  }

  return {
    host,
    port: parsePort(env.CIPHERNOTE_PORT),
    path,
    token: loadToken(env),
    allowedHosts: parseAllowedHosts(env.CIPHERNOTE_ALLOWED_HOSTS, host),
    maxBodyBytes,
    tls: certFile && keyFile
      ? { cert: readFileSync(certFile), key: readFileSync(keyFile), minVersion: "TLSv1.2" }
      : undefined,
  };
}

function secureEqual(left, right) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

export function hasValidBearer(authorization, expectedToken) {
  if (typeof authorization !== "string") return false;
  const match = /^Bearer ([^\s]+)$/.exec(authorization);
  return Boolean(match && secureEqual(match[1], expectedToken));
}

function sendJson(res, status, value, extraHeaders = {}) {
  const body = JSON.stringify(value);
  res.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "x-content-type-options": "nosniff",
    ...extraHeaders,
  });
  res.end(body);
}

async function readJsonBody(req, limit) {
  const declared = Number(req.headers["content-length"] || 0);
  if (Number.isFinite(declared) && declared > limit) {
    const error = new Error("request body too large");
    error.status = 413;
    throw error;
  }

  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) {
      const error = new Error("request body too large");
      error.status = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    const error = new Error("invalid JSON body");
    error.status = 400;
    throw error;
  }
}

export function createCipherNoteHttpService(config, serverFactory) {
  const handler = async (req, res) => {
    const requestUrl = new URL(req.url || "/", "http://localhost");
    const hostname = normalizeHostname(req.headers.host || "");

    if (!hostname || !config.allowedHosts.has(hostname)) {
      sendJson(res, 421, { error: "misdirected_request" });
      return;
    }
    if (requestUrl.pathname === "/healthz" && req.method === "GET") {
      sendJson(res, 200, { status: "ok" });
      return;
    }
    if (requestUrl.pathname !== config.path) {
      sendJson(res, 404, { error: "not_found" });
      return;
    }
    if (!hasValidBearer(req.headers.authorization, config.token)) {
      sendJson(res, 401, { error: "unauthorized" }, { "www-authenticate": "Bearer" });
      return;
    }
    if (!["GET", "POST", "DELETE"].includes(req.method)) {
      sendJson(res, 405, { error: "method_not_allowed" }, { allow: "GET, POST, DELETE" });
      return;
    }

    let mcpServer;
    try {
      const parsedBody = req.method === "POST" ? await readJsonBody(req, config.maxBodyBytes) : undefined;
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      mcpServer = serverFactory();
      await mcpServer.connect(transport);
      await transport.handleRequest(req, res, parsedBody);
    } catch (error) {
      if (!res.headersSent) {
        const status = Number.isInteger(error.status) ? error.status : 500;
        sendJson(res, status, { error: status === 500 ? "internal_error" : error.message });
      }
      if (error.status !== 400 && error.status !== 413) {
        console.error("CipherNote HTTP request failed:", error?.message || "unknown error");
      }
    } finally {
      if (mcpServer) await mcpServer.close().catch(() => {});
    }
  };

  const service = config.tls ? createHttpsServer(config.tls, handler) : createHttpServer(handler);
  service.headersTimeout = 10_000;
  service.requestTimeout = 30_000;
  service.keepAliveTimeout = 65_000;
  return service;
}

export async function listenHttpService(config, serverFactory) {
  const service = createCipherNoteHttpService(config, serverFactory);
  await new Promise((resolve, reject) => {
    service.once("error", reject);
    service.listen(config.port, config.host, resolve);
  });
  const address = service.address();
  const port = typeof address === "object" && address ? address.port : config.port;
  const scheme = config.tls ? "https" : "http";
  console.error(`CipherNote MCP listening on ${scheme}://${config.host}:${port}${config.path}`);
  return service;
}
