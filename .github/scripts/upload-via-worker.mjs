import { open, stat } from "node:fs/promises";
import { workflowToken } from "./worker-identity.mjs";

async function invoke(path, payload, raw = false) {
  for (let attempt = 0; attempt < 4; attempt++) {
    try {
      const response = await fetch(new URL(path, process.env.CF_WORKER_URL), {
        method: "POST", redirect: "error",
        headers: { Authorization: "Bearer " + await workflowToken(), "Content-Type": raw ? "application/octet-stream" : "application/json" },
        body: raw ? payload : JSON.stringify(payload),
      });
      if (!response.ok) {
        await response.body?.cancel();
        if (response.status < 500 && response.status !== 429) throw new Error("上传服务拒绝请求，状态码 " + response.status);
        throw new Error("上传服务暂时不可用");
      }
      return await response.json();
    } catch (error) {
      if (attempt === 3 || error.message.includes("拒绝请求")) throw error;
      await new Promise(resolve => setTimeout(resolve, (attempt + 1) * 2000));
    }
  }
}

export async function uploadArtifact(target, filename, contentType) {
  const url = new URL(target);
  const match = url.pathname.match(/^\/uploads\/repos\/[^/]+\/[^/]+\/releases\/([0-9]+)\/assets$/);
  if (!match || url.origin !== new URL(process.env.CF_WORKER_URL).origin) throw new Error("产物上传地址无效");
  const size = (await stat(filename)).size;
  const started = await invoke("/v1/assets/start", { releaseID: Number(match[1]), size, name: url.searchParams.get("name"), contentType });
  const file = await open(filename, "r");
  let completed = false;
  try {
    const parts = [];
    for (let position = 0, number = 1; position < size; number++) {
      const length = Math.min(started.partSize, size - position);
      const buffer = Buffer.alloc(length);
      let read = 0;
      while (read < length) {
        const result = await file.read(buffer, read, length - read, position + read);
        if (!result.bytesRead) throw new Error("产物文件在上传过程中发生变化");
        read += result.bytesRead;
      }
      parts.push(await invoke("/v1/assets/part?ticket=" + encodeURIComponent(started.ticket) + "&part=" + number, buffer, true));
      position += length;
    }
    const result = await invoke("/v1/assets/complete", { ticket: started.ticket, parts });
    completed = true;
    return result;
  } finally {
    await file.close();
    if (!completed) await invoke("/v1/assets/abort", { ticket: started.ticket }).catch(() => {});
  }
}
