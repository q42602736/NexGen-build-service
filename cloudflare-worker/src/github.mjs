import { json, readJSON } from "./crypto.mjs";
import { workflowClaims } from "./identity.mjs";
import { requireReleaseOwner } from "./assets.mjs";

const allowedAccept = new Set(["application/vnd.github+json", "application/vnd.github.raw", "application/vnd.github.raw+json", "application/octet-stream"]);
const unsafeInput = /[\x00-\x1f\x7f`$"'\\;]/;

function policyFor(env, repository) {
  const policy = JSON.parse(env.REPOSITORY_POLICY || "{}");
  const result = policy.repositories?.[repository.toLowerCase()];
  if (!result) throw new Error("仓库不在授权范围内");
  return { ...result, buildRepository: policy.buildRepository?.toLowerCase(), workflows: policy.workflows || [] };
}

function cleanSegments(path) {
  const segments = path.split("/").slice(1).map(value => decodeURIComponent(value));
  if (segments.some(s => !s || s === "." || s === ".." || /[\x00-\x1f\\]/.test(s))) throw new Error("请求路径无效");
  return segments;
}

function profilePath(path, policy) {
  return path === "profiles" || path.startsWith("profiles/") || path === "profile-assets" || path.startsWith("profile-assets/") || (policy.configPaths || []).includes(path);
}

function sourceRefAllowed(ref, policy) {
  return typeof ref === "string" && !unsafeInput.test(ref) && (policy.sourceBranches || []).includes(ref);
}

function authorizeOperation(method, pieces, url, payload, policy, role, repository) {
  const path = pieces.join("/");
  if (pieces[0] === "contents") {
    if (pieces.slice(1).some(value => value.includes("/") || /%[0-9a-f]{2}/i.test(value))) return false;
    if (!profilePath(pieces.slice(1).join("/"), policy)) return false;
    const branch = method === "GET" ? url.searchParams.get("ref") : payload?.branch;
    const allowed = method === "GET" ? [...(policy.profileBranches || []), ...(policy.configBranches || [])] : policy.profileBranches || [];
    return allowed.includes(branch) && (method === "GET" || (role === "server" && ["PUT", "DELETE"].includes(method)));
  }
  if (role === "workflow") {
    if (repository.toLowerCase() !== policy.buildRepository) return false;
    if (method === "GET" && /^releases(?:\/tags\/.+|\/[0-9]+(?:\/assets)?|\/assets\/[0-9]+)?$/.test(path)) return true;
    if (method === "POST" && path === "releases") {
      const fields = new Set(["tag_name", "target_commitish", "name", "body", "draft", "prerelease", "make_latest"]);
      return payload && Object.keys(payload).every(key => fields.has(key)) && typeof payload.tag_name === "string" && payload.tag_name.length <= 500 && !unsafeInput.test(payload.tag_name) && (!payload.target_commitish || payload.target_commitish === "main");
    }
    if (method === "PATCH" && /^releases\/[0-9]+$/.test(path)) return payload && Object.keys(payload).every(key => ["name", "body", "draft", "prerelease", "make_latest"].includes(key));
    if (method === "DELETE" && /^releases\/[0-9]+$/.test(path)) return true;
    return method === "DELETE" && /^releases\/assets\/[0-9]+$/.test(path);
  }
  if (role !== "server") return false;
  if (method === "GET") {
    if (!path || path === "branches" || path === "commits") return true;
    if (path.startsWith("git/ref/heads/")) return [...(policy.profileBranches || []), ...(policy.sourceBranches || [])].includes(pieces.slice(3).join("/"));
    if (/^releases(?:\/tags\/.+|\/[0-9]+(?:\/assets)?|\/assets\/[0-9]+)?$/.test(path)) return true;
    if (/^actions\/(?:workflows\/[^/]+\/runs|runs(?:\/[0-9]+(?:\/jobs)?)?)$/.test(path)) return true;
  }
  if (method === "POST" && path === "git/refs") {
    return (policy.profileBranches || []).some(branch => payload?.ref === "refs/heads/" + branch) && /^[0-9a-f]{40}$/i.test(payload?.sha || "");
  }
  if (repository.toLowerCase() !== policy.buildRepository) return false;
  if (method === "DELETE" && /^releases\/[0-9]+$/.test(path)) return true;
  if (method === "DELETE" && /^actions\/runs\/[0-9]+$/.test(path)) return true;
  if (method === "POST" && /^actions\/runs\/[0-9]+\/(?:cancel|force-cancel)$/.test(path)) return true;
  if (method === "POST" && pieces[0] === "actions" && pieces[1] === "workflows" && pieces[3] === "dispatches" && pieces.length === 4 && policy.workflows.includes(pieces[2])) {
    if (payload?.ref !== "main" || !payload.inputs || typeof payload.inputs !== "object") return false;
    const keys = new Set(["client", "profile", "profile_branch", "tag", "platforms", "branch", "core", "request_id"]);
    if (Object.entries(payload.inputs).some(([key, value]) => !keys.has(key) || typeof value !== "string" || value.length > 2000 || unsafeInput.test(value))) return false;
    const sourceRepository = payload.inputs.client === "nexgen_react" ? "q42602736/nexgen-client-react" : payload.inputs.core === "xray" ? "q42602736/nexgen-client-xray" : "q42602736/xboard-mihomo_sub";
    const sourcePolicy = JSON.parse(policy.policySource || "{}");
    return sourceRefAllowed(payload.inputs.branch, sourcePolicy[sourceRepository] || {}) && payload.inputs.profile && !payload.inputs.profile.includes("/");
  }
  return false;
}

function responseHeaders(response) {
  const headers = new Headers({ "Cache-Control": "no-store" });
  for (const [key, value] of response.headers) {
    if (["content-type", "content-disposition", "etag", "x-github-request-id", "x-github-api-version-selected"].includes(key.toLowerCase()) || key.toLowerCase().startsWith("x-ratelimit-")) headers.set(key, value);
  }
  return headers;
}

export async function githubRequest(request, env, role) {
  const url = new URL(request.url);
  const path = url.pathname.slice("/github".length);
  const segments = cleanSegments(path);
  if (segments[0] !== "repos" || segments.length < 3) return json({ error: "仅支持已授权的仓库接口" }, 403);
  const repository = segments[1] + "/" + segments[2];
  const policy = policyFor(env, repository);
  policy.policySource = JSON.stringify(JSON.parse(env.REPOSITORY_POLICY).repositories);
  const pieces = segments.slice(3);
  let payload;
  if (["PUT", "POST", "DELETE"].includes(request.method) && request.body) payload = await readJSON(request, 32 * 1024 * 1024);
  if (!authorizeOperation(request.method, pieces, url, payload, policy, role, repository)) return json({ error: "操作不在授权范围内" }, 403);
  if (role === "workflow" && request.method !== "GET") {
    const runID = workflowClaims(request).run_id;
    if (pieces.length === 1 && !payload.tag_name.endsWith("-" + runID)) return json({ error: "发布标签不属于本次构建" }, 403);
    if (pieces.length === 2) await requireReleaseOwner(env, pieces[1], runID);
    if (pieces[1] === "assets") {
      const assetResponse = await fetch("https://api.github.com" + path, { headers: { Authorization: "Bearer " + env.GITHUB_TOKEN, Accept: "application/vnd.github+json", "User-Agent": "nexgen-build-broker" }, redirect: "error" });
      if (!assetResponse.ok) return json({ error: "无法读取产物记录" }, assetResponse.status);
      const asset = await assetResponse.json();
      const assetURL = new URL(asset.browser_download_url);
      const parts = assetURL.pathname.split("/");
      const tag = decodeURIComponent(parts[parts.indexOf("download") + 1] || "");
      if (!tag.endsWith("-" + runID)) return json({ error: "产物不属于本次构建" }, 403);
    }
  }
  const suppliedAccept = request.headers.get("Accept");
  const accept = !suppliedAccept || suppliedAccept === "*/*" ? "application/vnd.github+json" : suppliedAccept;
  if (!allowedAccept.has(accept)) return json({ error: "响应格式无效" }, 400);
  const headers = { Authorization: "Bearer " + env.GITHUB_TOKEN, Accept: accept, "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "nexgen-build-broker" };
  if (payload !== undefined) headers["Content-Type"] = "application/json";
  let response = await fetch("https://api.github.com" + path + url.search, { method: request.method, headers, body: payload === undefined ? undefined : JSON.stringify(payload), redirect: "manual" });
  if ([301, 302, 303, 307, 308].includes(response.status)) {
    const location = response.headers.get("Location");
    const target = location && new URL(location);
    const trusted = target?.protocol === "https:" && ["release-assets.githubusercontent.com", "objects.githubusercontent.com"].includes(target.hostname);
    if (request.method !== "GET" || accept !== "application/octet-stream" || !trusted) {
      await response.body?.cancel();
      return json({ error: "上游返回了不允许的重定向" }, 502);
    }
    await response.body?.cancel();
    response = await fetch(target, { redirect: "error" });
  }
  if (pieces[0] === "releases" && accept !== "application/octet-stream" && response.headers.get("Content-Type")?.includes("json")) {
    const data = await response.json();
    for (const release of Array.isArray(data) ? data : [data]) {
      if (typeof release?.upload_url === "string") release.upload_url = release.upload_url.replace("https://uploads.github.com", env.WORKER_URL + "/uploads");
    }
    return new Response(JSON.stringify(data), { status: response.status, headers: responseHeaders(response) });
  }
  return new Response(response.status === 204 ? null : response.body, { status: response.status, headers: responseHeaders(response) });
}

export async function gitReadRequest(request, env, role) {
  if (role !== "workflow") return json({ error: "该凭证不能读取源码" }, 403);
  const url = new URL(request.url);
  const pieces = cleanSegments(url.pathname.slice("/git".length));
  if (pieces.length < 3) return json({ error: "Git 请求路径无效" }, 400);
  const repository = pieces[0] + "/" + pieces[1].replace(/\.git$/, "");
  const policy = policyFor(env, repository);
  if (!policy.gitRead) return json({ error: "源码仓库未授权" }, 403);
  const operation = pieces.slice(2).join("/");
  if (!(request.method === "GET" && operation === "info/refs" && url.searchParams.get("service") === "git-upload-pack") && !(request.method === "POST" && operation === "git-upload-pack")) return json({ error: "仅允许读取 Git 仓库" }, 403);
  const headers = { Authorization: "Basic " + btoa("x-access-token:" + env.GITHUB_TOKEN), "User-Agent": "nexgen-build-broker" };
  if (request.method === "POST") headers["Content-Type"] = "application/x-git-upload-pack-request";
  const protocol = request.headers.get("Git-Protocol");
  if (protocol && /^version=[012]$/.test(protocol)) headers["Git-Protocol"] = protocol;
  const response = await fetch("https://github.com/" + repository + ".git/" + operation + url.search, { method: request.method, headers, body: request.method === "POST" ? request.body : undefined, redirect: "manual" });
  if ([301, 302, 303, 307, 308].includes(response.status)) {
    await response.body?.cancel();
    return json({ error: "源码仓库发生了未授权重定向" }, 502);
  }
  return new Response(response.body, { status: response.status, headers: responseHeaders(response) });
}
