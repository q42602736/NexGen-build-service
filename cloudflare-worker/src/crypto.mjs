const encoder = new TextEncoder();
const decoder = new TextDecoder();
const hmacKeys = new Map();
let logPrivateKey;

export function json(data, status = 200) {
  return Response.json(data, { status, headers: { "Cache-Control": "no-store" } });
}

export async function equalSecret(expected, actual) {
  if (!expected || !actual) return false;
  const [left, right] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(expected)),
    crypto.subtle.digest("SHA-256", encoder.encode(actual)),
  ]);
  const a = new Uint8Array(left);
  const b = new Uint8Array(right);
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i];
  return difference === 0;
}

export async function readJSON(request, limit = 1024 * 1024) {
  if (Number(request.headers.get("Content-Length")) > limit) throw new Error("请求内容过大");
  const reader = request.body?.getReader();
  if (!reader) throw new Error("请求内容为空");
  const chunks = [];
  let size = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel();
      throw new Error("请求内容过大");
    }
    chunks.push(value);
  }
  const data = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    data.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(decoder.decode(data));
}

function decodeBase64(value) {
  return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

export function encodeBase64URL(bytes) {
  let value = "";
  for (const byte of new Uint8Array(bytes)) value += String.fromCharCode(byte);
  return btoa(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function decodeBase64URL(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("令牌格式无效");
  return decodeBase64(value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4));
}

async function hmacKey(secret) {
  if (!secret) throw new Error("签名密钥未配置");
  if (!hmacKeys.has(secret)) {
    hmacKeys.set(secret, crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]));
  }
  return hmacKeys.get(secret);
}

export async function signature(secret, bytes) {
  const result = await crypto.subtle.sign("HMAC", await hmacKey(secret), bytes);
  return Array.from(new Uint8Array(result), b => b.toString(16).padStart(2, "0")).join("");
}

export async function verifySignature(secret, supplied, bytes) {
  if (!/^[a-fA-F0-9]{64}$/.test(supplied || "")) return false;
  const value = Uint8Array.from(supplied.match(/../g), b => parseInt(b, 16));
  return crypto.subtle.verify("HMAC", await hmacKey(secret), value, bytes);
}

function validClaims(claims, kind) {
  if (!claims || typeof claims !== "object" || Array.isArray(claims)) return false;
  if (kind === "download") {
    return claims.sub === "build_asset_download" && Number.isSafeInteger(claims.record_id) && claims.record_id > 0 && Number.isSafeInteger(claims.asset_id) && claims.asset_id > 0;
  }
  return kind === "session" && Number.isSafeInteger(claims.code_id) && claims.code_id >= 0 && ["admin", "user"].includes(claims.permissions) && typeof claims.code_name === "string" && claims.code_name.length <= 500;
}

export async function signToken(secret, claims, kind) {
  const now = Math.floor(Date.now() / 1000);
  if (!validClaims(claims, kind) || !Number.isSafeInteger(claims.exp) || claims.exp <= now || claims.exp > now + 86400) throw new Error("令牌声明无效");
  const allowed = kind === "download" ? ["record_id", "asset_id", "sub", "exp", "iat", "nbf"] : ["code_id", "code_name", "permissions", "allowed_profiles", "allowed_clients", "exp", "iat", "nbf"];
  const payload = Object.fromEntries(allowed.filter(k => Object.hasOwn(claims, k)).map(k => [k, claims[k]]));
  const header = encodeBase64URL(encoder.encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const body = encodeBase64URL(encoder.encode(JSON.stringify(payload)));
  const content = header + "." + body;
  return content + "." + encodeBase64URL(await crypto.subtle.sign("HMAC", await hmacKey(secret), encoder.encode(content)));
}

export async function verifyToken(secret, token, kind) {
  if (typeof token !== "string" || token.length > 32768) throw new Error("令牌格式无效");
  const pieces = token.split(".");
  if (pieces.length !== 3) throw new Error("令牌格式无效");
  const header = JSON.parse(decoder.decode(decodeBase64URL(pieces[0])));
  if (header.alg !== "HS256" || header.crit) throw new Error("令牌签名算法无效");
  const valid = await crypto.subtle.verify("HMAC", await hmacKey(secret), decodeBase64URL(pieces[2]), encoder.encode(pieces[0] + "." + pieces[1]));
  if (!valid) throw new Error("令牌签名无效");
  const claims = JSON.parse(decoder.decode(decodeBase64URL(pieces[1])));
  const now = Date.now() / 1000;
  if (!validClaims(claims, kind) || !Number.isFinite(claims.exp) || claims.exp <= now || (claims.nbf !== undefined && (!Number.isFinite(claims.nbf) || claims.nbf > now))) throw new Error("令牌无效或已过期");
  return claims;
}

export async function decryptLogBatch(env, payload) {
  if (!payload.header?.key || !Array.isArray(payload.lines) || payload.lines.length > 32) throw new Error("日志解密请求无效");
  if (!logPrivateKey) {
    const pem = env.SECURE_LOG_PRIVATE_KEY;
    if (!pem) throw new Error("日志解密私钥未配置");
    const der = decodeBase64(pem.replace(/-----[^-]+-----/g, "").replace(/\s/g, ""));
    logPrivateKey = crypto.subtle.importKey("pkcs8", der, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
  }
  const rawKey = await crypto.subtle.decrypt("RSA-OAEP", await logPrivateKey, decodeBase64(payload.header.key));
  const key = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["decrypt"]);
  const lines = [];
  for (const line of payload.lines) {
    try {
      const record = JSON.parse(line);
      const nonce = decodeBase64(record.n);
      if (nonce.length !== 12) throw new Error("日志随机数格式无效");
      const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, decodeBase64(record.c));
      lines.push({ text: decoder.decode(plain) });
    } catch {
      lines.push({ error: "日志记录解密失败" });
    }
  }
  return { lines };
}
