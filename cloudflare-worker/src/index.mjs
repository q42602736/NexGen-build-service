import { decryptLogBatch, equalSecret, json, readJSON, signature, signToken, verifySignature, verifyToken } from "./crypto.mjs";
import { githubRequest, gitReadRequest } from "./github.mjs";
import { isGitHubWorkflow } from "./identity.mjs";
import { assetRequest } from "./assets.mjs";

const encoder = new TextEncoder();

async function requestRole(request, env) {
  const authorization = request.headers.get("Authorization") || "";
  let token = authorization.replace(/^(?:Bearer|token)\s+/i, "");
  if (authorization.startsWith("Basic ")) {
    try { token = atob(authorization.slice(6)).split(":").slice(1).join(":"); } catch { return null; }
  }
  if (await equalSecret(env.SERVER_TOKEN, token)) return "server";
  if (await isGitHubWorkflow(token, env)) return "workflow";
  return null;
}

async function callback(request, env, path) {
  if (request.method !== "POST") return json({ error: "请求方法无效" }, 405);
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.length > 5 * 1024 * 1024) return json({ error: "回调内容过大" }, 413);
  const headers = new Headers({ "Content-Type": "application/json", "X-Worker-Callback-Token": env.SERVER_TOKEN });
  if (path === "/api/internal/github/webhook") {
    const supplied = (request.headers.get("X-Hub-Signature-256") || "").replace(/^sha256=/, "");
    if (!env.GITHUB_WEBHOOK_SECRET || !await verifySignature(env.GITHUB_WEBHOOK_SECRET, supplied, bytes)) return json({ error: "Webhook 签名无效" }, 401);
    headers.set("X-GitHub-Event", request.headers.get("X-GitHub-Event") || "");
    headers.set("X-GitHub-Delivery", request.headers.get("X-GitHub-Delivery") || "");
    headers.set("X-Worker-Webhook-Signature", await signature(env.SERVER_TOKEN, bytes));
    if (env.ORIGIN_MODE === "legacy") headers.set("X-Hub-Signature-256", "sha256=" + supplied);
  } else {
    const workflowIdentity = await requestRole(request, env);
    if (workflowIdentity !== "workflow" && !await equalSecret(env.BUILD_EVENT_TOKEN, request.headers.get("X-Build-Event-Token"))) return json({ error: "构建回调凭证无效" }, 401);
    if (env.ORIGIN_MODE === "legacy") headers.set("X-Build-Event-Token", env.BUILD_EVENT_TOKEN);
  }
  const origin = new URL(env.ORIGIN_URL);
  if (origin.protocol !== "https:") throw new Error("后端地址必须使用 HTTPS");
  const response = await fetch(new URL(path, origin), { method: "POST", headers, body: bytes, redirect: "error" });
  return new Response(response.body, { status: response.status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
}

export default {
  async fetch(request, env) {
    try {
      const path = new URL(request.url).pathname;
      if (path === "/health" && request.method === "GET") return json({ status: "ok", service: "nexgen-build-broker" });
      if (["/api/internal/build-events/bind", "/api/internal/build-events/progress", "/api/internal/build-events/complete", "/api/internal/github/webhook"].includes(path)) return await callback(request, env, path);
      const role = await requestRole(request, env);
      if (!role) return json({ error: "调用凭证无效" }, 401);
      if (path.startsWith("/github/")) return await githubRequest(request, env, role);
      if (path.startsWith("/git/")) return await gitReadRequest(request, env, role);
      if (path.startsWith("/v1/assets/") && role === "workflow") return await assetRequest(request, env, path);
      if (role !== "server") return json({ error: "操作未授权" }, 403);
      if (request.method !== "POST") return json({ error: "请求方法无效" }, 405);
      const payload = await readJSON(request, path === "/v1/logs/decrypt" ? 32 * 1024 * 1024 : 1024 * 1024);
      if (path === "/v1/auth/sign") return json({ token: await signToken(env.JWT_SECRET, payload.claims, payload.kind) });
      if (path === "/v1/auth/verify") {
        try { return json({ claims: await verifyToken(env.JWT_SECRET, payload.token, payload.kind) }); } catch { return json({ error: "令牌无效或已过期" }, 401); }
      }
      if (path === "/v1/auth/admin") return json({ valid: await equalSecret(env.ADMIN_PASSWORD, payload.password) });
      if (path === "/v1/logs/decrypt") return json(await decryptLogBatch(env, payload));
      return json({ error: "接口不存在" }, 404);
    } catch {
      // 只返回固定错误，避免上游错误或请求内容带出凭证。
      return json({ error: "请求处理失败，请检查请求格式或服务配置" }, 400);
    }
  },
};
