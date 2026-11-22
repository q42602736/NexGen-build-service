export async function workflowToken() {
  const worker = process.env.CF_WORKER_URL;
  const endpoint = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const credential = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!worker || !endpoint || !credential) throw new Error("缺少 Worker 地址或 GitHub OIDC 身份配置");
  const url = new URL(endpoint);
  if (url.protocol !== "https:" || !url.hostname.endsWith(".actions.githubusercontent.com")) throw new Error("GitHub 身份服务地址无效");
  url.searchParams.set("audience", new URL(worker).origin);
  const response = await fetch(url, { headers: { Authorization: "Bearer " + credential }, redirect: "error" });
  if (!response.ok) throw new Error("获取 GitHub 身份令牌失败");
  const data = await response.json();
  if (typeof data.value !== "string" || !data.value) throw new Error("GitHub 身份响应无效");
  console.error("::add-mask::" + data.value);
  console.error("::add-mask::" + Buffer.from("x-access-token:" + data.value).toString("base64"));
  return data.value;
}
