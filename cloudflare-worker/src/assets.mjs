import { fetchWithoutRedirect } from "./crypto.mjs";

function repository(env) {
  return JSON.parse(env.REPOSITORY_POLICY).buildRepository;
}

export async function releaseMetadata(env, releaseID) {
  const response = await fetchWithoutRedirect("https://api.github.com/repos/" + repository(env) + "/releases/" + releaseID, {
    headers: { Authorization: "Bearer " + env.GITHUB_TOKEN, Accept: "application/vnd.github+json", "User-Agent": "nexgen-build-broker" },
  });
  if (!response.ok) throw new Error("无法读取发布记录");
  return response.json();
}

export async function requireReleaseOwner(env, releaseID, runID) {
  const release = await releaseMetadata(env, releaseID);
  if (!String(release.tag_name).endsWith("-" + runID)) throw new Error("该发布记录不属于本次构建");
  return release;
}
