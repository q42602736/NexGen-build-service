import { decodeBase64URL } from "./crypto.mjs";

const decoder = new TextDecoder();
const encoder = new TextEncoder();
let signingKeys;
let refreshedAt = 0;

export function workflowClaims(request) {
  const token = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  return JSON.parse(decoder.decode(decodeBase64URL(token.split(".")[1])));
}

export async function isGitHubWorkflow(token, env) {
  if (typeof token !== "string" || token.length > 32768) return false;
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return false;
    const header = JSON.parse(decoder.decode(decodeBase64URL(parts[0])));
    const claims = JSON.parse(decoder.decode(decodeBase64URL(parts[1])));
    const policy = JSON.parse(env.REPOSITORY_POLICY || "{}");
    const now = Date.now() / 1000;
    if (header.alg !== "RS256" || typeof header.kid !== "string" || header.crit) return false;
    if (claims.iss !== "https://token.actions.githubusercontent.com" || claims.aud !== new URL(env.WORKER_URL).origin) return false;
    if (claims.repository !== policy.buildRepository || String(claims.repository_id) !== String(policy.repositoryId)) return false;
    if (claims.ref !== "refs/heads/main" || claims.event_name !== "workflow_dispatch") return false;
    if (!policy.workflows.some(file => claims.workflow_ref === policy.buildRepository + "/.github/workflows/" + file + "@refs/heads/main")) return false;
    if (!Number.isFinite(claims.exp) || claims.exp <= now || !Number.isFinite(claims.nbf) || claims.nbf > now + 30) return false;
    if (!signingKeys || Date.now() - refreshedAt > 300000) {
      const response = await fetch("https://token.actions.githubusercontent.com/.well-known/jwks", { redirect: "error" });
      if (!response.ok) return false;
      const data = await response.json();
      signingKeys = data.keys;
      refreshedAt = Date.now();
    }
    const jwk = signingKeys.find(key => key.kid === header.kid && key.kty === "RSA");
    if (!jwk) return false;
    const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    return crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, decodeBase64URL(parts[2]), encoder.encode(parts[0] + "." + parts[1]));
  } catch {
    return false;
  }
}
