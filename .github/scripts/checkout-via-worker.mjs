import { spawn } from "node:child_process";
import { workflowToken } from "./worker-identity.mjs";

async function git(args) {
  const worker = new URL(process.env.CF_WORKER_URL);
  if (worker.protocol !== "https:") throw new Error("Worker 地址必须使用 HTTPS");
  const token = await workflowToken();
  const prefix = worker.origin + "/git/";
  // 凭证只传给 Git 子进程，不写入 URL 或 Git 配置文件。
  const config = [
    ["http." + worker.origin + "/.extraheader", "Authorization: Basic " + Buffer.from("x-access-token:" + token).toString("base64")],
    ["url." + prefix + ".insteadOf", "https://github.com/"],
    ["url." + prefix + ".insteadOf", "git@github.com:"],
    ["url." + prefix + ".insteadOf", "ssh://git@github.com/"],
    ["protocol.file.allow", "never"],
  ];
  const env = { ...process.env, GIT_CONFIG_COUNT: String(config.length), GIT_TERMINAL_PROMPT: "0" };
  config.forEach(([key, value], index) => { env["GIT_CONFIG_KEY_" + index] = key; env["GIT_CONFIG_VALUE_" + index] = value; });
  await new Promise((resolve, reject) => {
    const child = spawn("git", args, { env, stdio: "inherit", shell: false });
    child.on("error", () => reject(new Error("无法执行 Git")));
    child.on("exit", code => code === 0 ? resolve() : reject(new Error("源码读取失败")));
  });
}

try {
  const repository = process.env.SOURCE_REPO;
  const ref = process.env.SOURCE_REF;
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository || "") || !ref || ref.startsWith("-")) throw new Error("源码仓库或版本参数无效");
  await git(["clone", "--no-checkout", "https://github.com/" + repository + ".git", "source"]);
  await git(["-C", "source", "checkout", "--detach", ref]);
  await git(["-C", "source", "submodule", "sync", "--recursive"]);
  await git(["-C", "source", "submodule", "update", "--init", "--recursive"]);
  console.log("源码及子模块读取完成，未保存 GitHub 访问凭证");
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
