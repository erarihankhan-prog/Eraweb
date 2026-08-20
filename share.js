import crypto from "node:crypto";

const ALGORITHM = "aes-256-gcm";
const TOKEN_VERSION = "v1";
const MAX_NAME_LENGTH = 80;
const MAX_PATH_LENGTH = 300;

function json(data, status = 200) {
  return {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store, max-age=0",
      "X-Content-Type-Options": "nosniff",
      "Access-Control-Allow-Origin": "same-origin",
      "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Accept"
    },
    body: JSON.stringify(data)
  };
}

function readBody(req) {
  if (!req.body) return {};
  if (typeof req.body === "object") return req.body;
  try { return JSON.parse(req.body); } catch { return {}; }
}

function getSecret() {
  const raw = process.env.SHARE_ENCRYPTION_KEY || "";
  if (!/^[a-f0-9]{64}$/i.test(raw)) {
    throw new Error("SHARE_ENCRYPTION_KEY must be a 64-character hex value");
  }
  return Buffer.from(raw, "hex");
}

function toBase64Url(value) {
  return Buffer.from(value).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(normalized + "=".repeat((4 - normalized.length % 4) % 4), "base64");
}

function encrypt(record) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, getSecret(), iv);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(record), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [TOKEN_VERSION, toBase64Url(iv), toBase64Url(tag), toBase64Url(ciphertext)].join(".");
}

function decrypt(token) {
  if (typeof token !== "string") throw new Error("Missing share token");
  const [version, ivPart, tagPart, ciphertextPart] = token.split(".");
  if (version !== TOKEN_VERSION || !ivPart || !tagPart || !ciphertextPart) throw new Error("Invalid share token");
  const decipher = crypto.createDecipheriv(ALGORITHM, getSecret(), fromBase64Url(ivPart));
  decipher.setAuthTag(fromBase64Url(tagPart));
  const plaintext = Buffer.concat([decipher.update(fromBase64Url(ciphertextPart)), decipher.final()]).toString("utf8");
  const record = JSON.parse(plaintext);
  if (!record || typeof record !== "object" || !record.name || !record.url || !record.key) throw new Error("Invalid share record");
  if (record.exp && Date.now() > record.exp) throw new Error("Share link expired");
  return record;
}

function normalizeFirebaseUrl(value) {
  const url = String(value || "").trim().replace(/\/$/, "");
  if (!/^https:\/\/[a-z0-9_-]+\.(firebaseio\.com|firebasedatabase\.app)$/i.test(url)) {
    throw new Error("Only an HTTPS Firebase Realtime Database URL is allowed");
  }
  return url;
}

function safePath(value) {
  const path = String(value || "").replace(/^\/+|\/+$/g, "");
  if (!path || path.length > MAX_PATH_LENGTH || path.includes("..") || !/^[A-Za-z0-9_./-]+$/.test(path)) {
    throw new Error("Invalid database path");
  }
  return path;
}

function buildTarget(record, path, query) {
  const target = new URL(`${normalizeFirebaseUrl(record.url)}/${safePath(path)}.json`);
  target.searchParams.set("auth", record.key);
  if (query && typeof query === "object") {
    for (const [key, value] of Object.entries(query)) {
      if (!/^[A-Za-z][A-Za-z0-9_]*$/.test(key)) continue;
      target.searchParams.set(key, String(value));
    }
  }
  return target;
}

async function proxyFirebase(record, operation) {
  const method = String(operation?.method || "GET").toUpperCase();
  if (!["GET", "PUT", "DELETE"].includes(method)) throw new Error("Unsupported database operation");
  const target = buildTarget(record, operation?.path, operation?.query);
  const options = { method, headers: { Accept: "application/json" }, signal: AbortSignal.timeout(15000) };
  if (method === "PUT") {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(operation.data === undefined ? null : operation.data);
  }
  const response = await fetch(target, options);
  const bodyText = await response.text();
  let data;
  try { data = bodyText ? JSON.parse(bodyText) : null; } catch { data = bodyText.slice(0, 500); }
  if (!response.ok) {
    const error = response.status === 401 || response.status === 403 ? "Firebase permission denied" : `Firebase HTTP ${response.status}`;
    throw new Error(error);
  }
  return data;
}

async function route(req) {
  if (req.method === "OPTIONS") return json({}, 204);
  try {
    if (req.method === "POST") {
      const body = readBody(req);
      const name = String(body.name || "").trim().slice(0, MAX_NAME_LENGTH);
      const url = normalizeFirebaseUrl(body.url);
      const key = String(body.key || "").trim();
      if (!name || !key) return json({ error: "Friendly Name, Firebase URL, and authentication key are required" }, 400);
      const token = encrypt({ name, url, key, iat: Date.now(), exp: Date.now() + 30 * 24 * 60 * 60 * 1000 });
      return json({ token, name });
    }

    const requestUrl = new URL(req.url, "http://localhost");
    const record = decrypt(requestUrl.searchParams.get("token"));
    if (req.method === "GET") return json({ name: record.name, shared: true });
    if (req.method === "PUT") return json({ data: await proxyFirebase(record, readBody(req)) });
    return json({ error: "Method not allowed" }, 405);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Share request failed";
    const status = /expired|invalid|missing|allowed|required|path|operation|method/i.test(message) ? 400 : 500;
    return json({ error: message }, status);
  }
}

export default async function handler(req, res) {
  const result = await route(req);
  if (res && typeof res.status === "function") {
    res.status(result.status);
    for (const [key, value] of Object.entries(result.headers || {})) res.setHeader(key, value);
    res.end(result.body);
    return;
  }
  return result;
}
