import { spawn } from "node:child_process";
import { workflowToken } from "./worker-identity.mjs";
import { uploadArtifact } from "./upload-via-worker.mjs";

try {
  const input = process.argv.slice(2);
  const origin = new URL(process.env.CF_WORKER_URL).origin;
  const targets = input.filter(value => /^https?:\/\//.test(value));
  if (targets.length !== 1 || new URL(targets[0]).origin !== origin) throw new Error("Worker 请求目标无效");
  const uploadIndex = input.findIndex(value => ["--upload-file", "-T"].includes(value));
  if (uploadIndex >= 0) {
    let contentType = "application/octet-stream";
    for (let i = 0; i < input.length; i++) {
      if (["-H", "--header"].includes(input[i]) && /^content-type:/i.test(input[i + 1] || "")) contentType = input[i + 1].slice("content-type:".length).trim();
    }
    console.log(JSON.stringify(await uploadArtifact(targets[0], input[uploadIndex + 1], contentType)));
  } else {
  const args = [];
  for (let i = 0; i < input.length; i++) {
    if (["-H", "--header"].includes(input[i]) && /^(?:authorization|x-build-event-token):/i.test(input[i + 1] || "")) { i++; continue; }
    args.push(input[i]);
  }
  args.push("--max-redirs", "0", "-H", "Authorization: Bearer " + await workflowToken());
  const child = spawn("curl", args, { stdio: "inherit", shell: false });
  child.on("error", () => { console.error("无法执行 Worker 请求"); process.exitCode = 1; });
  child.on("exit", code => { process.exitCode = code ?? 1; });
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
