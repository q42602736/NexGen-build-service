import { decodeBase64URL, encodeBase64URL, json, readJSON, signature, verifySignature } from "./crypto.mjs";
import { workflowClaims } from "./identity.mjs";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const partSize = 8 * 1024 * 1024;

function repository(env) {
  return JSON.parse(env.REPOSITORY_POLICY).buildRepository;
}

export async function releaseMetadata(env, releaseID) {
  const response = await fetch("https://api.github.com/repos/" + repository(env) + "/releases/" + releaseID, {
    headers: { Authorization: "Bearer " + env.GITHUB_TOKEN, Accept: "application/vnd.github+json", "User-Agent": "nexgen-build-broker" }, redirect: "error",
  });
  if (!response.ok) throw new Error("无法读取发布记录");
  return response.json();
}

export async function requireReleaseOwner(env, releaseID, runID) {
  const release = await releaseMetadata(env, releaseID);
  if (!String(release.tag_name).endsWith("-" + runID)) throw new Error("该发布记录不属于本次构建");
  return release;
}

async function createTicket(env, values) {
  const body = encodeBase64URL(encoder.encode(JSON.stringify(values)));
  return body + "." + await signature(env.JWT_SECRET, encoder.encode("upload-ticket:" + body));
}

async function readTicket(env, token, runID) {
  const pieces = String(token || "").split(".");
  if (pieces.length !== 2 || !await verifySignature(env.JWT_SECRET, pieces[1], encoder.encode("upload-ticket:" + pieces[0]))) throw new Error("上传凭证无效");
  const value = JSON.parse(decoder.decode(decodeBase64URL(pieces[0])));
  if (String(value.runID) !== String(runID) || value.expiresAt <= Date.now()) throw new Error("上传凭证已失效");
  return value;
}

export async function assetRequest(request, env, path) {
  if (request.method !== "POST") return json({ error: "请求方法无效" }, 405);
  const runID = workflowClaims(request).run_id;
  if (!/^[0-9]+$/.test(String(runID))) return json({ error: "构建身份无效" }, 403);
  if (path === "/v1/assets/start") {
    const payload = await readJSON(request, 16384);
    if (!Number.isSafeInteger(payload.releaseID) || payload.releaseID <= 0 || !Number.isSafeInteger(payload.size) || payload.size <= 0 || payload.size > 2 * 1024 * 1024 * 1024) throw new Error("上传参数无效");
    if (typeof payload.name !== "string" || !payload.name || payload.name.length > 512 || /[\x00-\x1f/\\]/.test(payload.name)) throw new Error("产物名称无效");
    if (typeof payload.contentType !== "string" || payload.contentType.length > 200 || /[\r\n]/.test(payload.contentType)) throw new Error("产物类型无效");
    await requireReleaseOwner(env, payload.releaseID, runID);
    const key = "build-uploads/" + runID + "/" + crypto.randomUUID();
    const upload = await env.ARTIFACT_UPLOADS.createMultipartUpload(key);
    const ticket = await createTicket(env, { ...payload, key, uploadID: upload.uploadId, runID, expiresAt: Date.now() + 3600000 });
    return json({ ticket, partSize });
  }
  const url = new URL(request.url);
  const payload = path === "/v1/assets/part" ? null : await readJSON(request, 65536);
  const ticket = await readTicket(env, payload?.ticket || url.searchParams.get("ticket"), runID);
  const upload = env.ARTIFACT_UPLOADS.resumeMultipartUpload(ticket.key, ticket.uploadID);
  if (path === "/v1/assets/part") {
    const number = Number(url.searchParams.get("part"));
    const expected = Math.min(partSize, ticket.size - (number - 1) * partSize);
    if (!Number.isSafeInteger(number) || number < 1 || expected <= 0 || Number(request.headers.get("Content-Length")) !== expected) throw new Error("上传分片大小无效");
    return json(await upload.uploadPart(number, request.body));
  }
  if (path === "/v1/assets/abort") {
    await upload.abort().catch(() => {});
    await env.ARTIFACT_UPLOADS.delete(ticket.key);
    return json({ aborted: true });
  }
  if (path !== "/v1/assets/complete") return json({ error: "接口不存在" }, 404);
  if (!Array.isArray(payload.parts) || payload.parts.length !== Math.ceil(ticket.size / partSize) || payload.parts.some((part, index) => part.partNumber !== index + 1 || typeof part.etag !== "string")) throw new Error("上传分片列表无效");
  try {
    await upload.complete(payload.parts);
    const object = await env.ARTIFACT_UPLOADS.get(ticket.key);
    if (!object || object.size !== ticket.size) throw new Error("产物大小不一致");
    await requireReleaseOwner(env, ticket.releaseID, runID);
    const stream = new FixedLengthStream(object.size);
    const piping = object.body.pipeTo(stream.writable);
    const [response] = await Promise.all([
      fetch("https://uploads.github.com/repos/" + repository(env) + "/releases/" + ticket.releaseID + "/assets?name=" + encodeURIComponent(ticket.name), {
        method: "POST", body: stream.readable, redirect: "error",
        headers: { Authorization: "Bearer " + env.GITHUB_TOKEN, "Content-Type": ticket.contentType, "User-Agent": "nexgen-build-broker" },
      }),
      piping,
    ]);
    if (!response.ok) { await response.body?.cancel(); return json({ error: "GitHub 产物发布失败" }, response.status); }
    return json(await response.json(), response.status);
  } finally {
    await env.ARTIFACT_UPLOADS.delete(ticket.key);
  }
}
