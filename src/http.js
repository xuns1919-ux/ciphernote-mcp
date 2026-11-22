import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { callStore } from "./ciphernote.js";
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

  const privacyMode = (env.CIPHERNOTE_PRIVACY_MODE || "standard").trim().toLowerCase();
  if (!["standard", "private", "strict"].includes(privacyMode)) throw new Error("CIPHERNOTE_PRIVACY_MODE must be standard, private, or strict");
  const secureCaptureEnabled = env.CIPHERNOTE_SECURE_CAPTURE_ENABLED === "true" ||
    (env.CIPHERNOTE_SECURE_CAPTURE_ENABLED === undefined && privacyMode !== "standard");
  return {
    host,
    port: parsePort(env.CIPHERNOTE_PORT),
    path,
    token: loadToken(env),
    allowedHosts: parseAllowedHosts(env.CIPHERNOTE_ALLOWED_HOSTS, host),
    maxBodyBytes,
    privacyMode,
    secureCaptureEnabled,
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


const captureSessions = new Map();

function tokenSubject(token) {
  return createHash("sha256").update(token).digest("hex");
}

function captureSession(req) {
  const match = /(?:^|;\s*)ciphernote_capture=([^;]+)/.exec(req.headers.cookie || "");
  const session = match && captureSessions.get(match[1]);
  if (!session || session.expiresAt < Date.now()) return null;
  return session;
}

function sameOrigin(req, config) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try {
    const parsed = new URL(origin);
    return normalizeHostname(parsed.hostname) === normalizeHostname(req.headers.host || "") &&
      (parsed.protocol === "https:" || parsed.protocol === "http:") &&
      config.allowedHosts.has(normalizeHostname(parsed.hostname));
  } catch {
    return false;
  }
}

function capturePage(authenticated) {
  if (!authenticated) {
    return '<!doctype html><meta charset="utf-8"><title>CipherNote Secure Capture</title><h1>Secure Capture</h1><p>输入 Bearer Token 建立安全会话。</p><form id="f"><input id="t" type="password" required><button>登录</button></form><pre id="o"></pre><script>f.onsubmit=async(e)=>{e.preventDefault();const r=await fetch("/notes/capture/login",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({token:t.value})});o.textContent=r.ok?"登录成功，请刷新":"认证失败";if(r.ok)location.reload()}</script>';
  }
  return '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>CipherNote Secure Capture</title><h1>Secure Capture</h1><p>正文直接发送到服务端，不经过 MCP 工具参数。</p><form id="f"><input id="t" maxlength="200" placeholder="标题" required><textarea id="c" maxlength="100000" placeholder="正文" required></textarea><input id="g" placeholder="标签，用逗号分隔"><input id="i" type="number" min="0" max="5" value="0"><button type="button" id="s">安全保存</button><button type="button" id="d">创建暂存引用</button></form><pre id="o"></pre><script>const body=()=>({title:t.value,content:c.value,tags:g.value.split(",").map(x=>x.trim()).filter(Boolean),importance:Number(i.value)});async function send(path){const r=await fetch(path,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body())});o.textContent=JSON.stringify(await r.json(),null,2)};s.onclick=()=>send("/notes/capture/save");d.onclick=()=>send("/notes/capture/drafts")</script>';
}

async function handleCapture(req, res, requestUrl, config, readJsonBody) {
  if (!config.secureCaptureEnabled || !requestUrl.pathname.startsWith("/notes/capture")) return false;
  if (!sameOrigin(req, config)) { sendJson(res, 403, { error: "csrf_or_origin_rejected" }); return true; }
  const secure = config.tls || req.headers["x-forwarded-proto"] === "https";
  if (req.method === "GET" && requestUrl.pathname === "/notes/capture") {
    res.writeHead(200, { "cache-control": "no-store", "content-type": "text/html; charset=utf-8" });
    res.end(capturePage(Boolean(captureSession(req))));
    return true;
  }
  if (req.method === "POST" && requestUrl.pathname === "/notes/capture/login") {
    const body = await readJsonBody(req, config.maxBodyBytes);
    if (typeof body.token !== "string" || !hasValidBearer("Bearer " + body.token, config.token)) { sendJson(res, 401, { error: "unauthorized" }); return true; }
    const id = randomBytes(32).toString("base64url");
    captureSessions.set(id, { subject: tokenSubject(body.token), expiresAt: Date.now() + 3600000 });
    sendJson(res, 200, { success: true }, { "set-cookie": "ciphernote_capture=" + id + "; Path=/notes/capture; Max-Age=3600; HttpOnly; SameSite=Strict" + (secure ? "; Secure" : "") });
    return true;
  }
  const session = captureSession(req);
  if (!session) { sendJson(res, 401, { error: "capture_session_required" }); return true; }
  if (req.method !== "POST" || !["/notes/capture/save", "/notes/capture/drafts", "/notes/capture/read", "/notes/capture/delete"].includes(requestUrl.pathname)) { sendJson(res, 404, { error: "not_found" }); return true; }
  const body = await readJsonBody(req, config.maxBodyBytes);
  const args = { ...body, _secure_capture: true, _subject: session.subject };
  const action = requestUrl.pathname.endsWith("/save") ? "write" : requestUrl.pathname.endsWith("/drafts") ? "create_draft" : requestUrl.pathname.endsWith("/read") ? "read" : "delete";
  const response = await callStore(action, args, session.subject);
  sendJson(res, 200, response);
  return true;
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
    if (await handleCapture(req, res, requestUrl, config, readJsonBody)) return;
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
      const match = /^Bearer ([^\s]+)$/.exec(req.headers.authorization || "");
      mcpServer = serverFactory({ subject: tokenSubject(match ? match[1] : "") });
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
