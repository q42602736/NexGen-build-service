#!/bin/sh

set -eu
umask 077

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

mkdir -p dist
chmod 700 dist

OUTPUT="dist/nexgen-client"
TMP_OUTPUT="${OUTPUT}.tmp"
CONFIG_PATH=${NEXGEN_EMBED_CONFIG:-}
GARBLE_BIN=${GARBLE_BIN:-garble}

if [ -z "$CONFIG_PATH" ] || [ ! -f "$CONFIG_PATH" ]; then
  echo "请通过 NEXGEN_EMBED_CONFIG 指定受保护的专用构建 JSON 配置" >&2
  exit 1
fi

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/nexgen-embedded.XXXXXX")
cleanup() {
  rm -rf "$WORK_DIR"
  rm -f "$TMP_OUTPUT"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

python3 - "$CONFIG_PATH" "$WORK_DIR" "$SCRIPT_DIR" <<'PY'
import json, os, pathlib, stat, sys
source = pathlib.Path(sys.argv[1])
work = pathlib.Path(sys.argv[2])
root = pathlib.Path(sys.argv[3])
if stat.S_IMODE(source.stat().st_mode) & 0o077:
    raise SystemExit("专用配置文件必须仅允许所有者读取")
values = json.loads(source.read_text())
required = ("GITHUB_TOKEN", "GITHUB_OWNER", "GITHUB_REPO", "JWT_SECRET", "ADMIN_PASSWORD", "BUILD_EVENT_TOKEN", "GITHUB_WEBHOOK_SECRET", "SECURE_LOG_PRIVATE_KEY")
if not isinstance(values, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in values.items()):
    raise SystemExit("专用配置格式无效")
if any(not values.get(key) for key in required) or any(key.startswith("CF_WORKER_") for key in values):
    raise SystemExit("专用配置缺少必需字段或仍包含旧 Worker 配置")
lines = ["package main", "", "var embeddedEnvironment = map[string]string{"]
for key, value in sorted(values.items()):
    lines.append("\t" + json.dumps(key, ensure_ascii=False) + ": " + json.dumps(value, ensure_ascii=False) + ",")
lines.append("}")
replacement = work / "embedded_config.go"
replacement.write_text("\n".join(lines) + "\n")
os.chmod(replacement, 0o600)
overlay = {"Replace": {str(root / "embedded_config.go"): str(replacement)}}
(work / "overlay.json").write_text(json.dumps(overlay))
PY

: "${GOMAXPROCS:=2}"
: "${GOFLAGS:=-p=1}"
export GOMAXPROCS GOFLAGS

rm -f "$TMP_OUTPUT"

echo "开始生成配置内置的 Linux amd64 混淆二进制: $OUTPUT"
echo "构建限制: GOMAXPROCS=$GOMAXPROCS GOFLAGS=$GOFLAGS"

env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOGARBLE=config-server GOCACHE="$WORK_DIR/go-cache" GARBLE_CACHE="$WORK_DIR/garble-cache" \
  "$GARBLE_BIN" -literals -seed=random build -overlay "$WORK_DIR/overlay.json" -trimpath -ldflags='-s -w' -o "$TMP_OUTPUT" .
mv "$TMP_OUTPUT" "$OUTPUT"
chmod 600 "$OUTPUT"

echo "已生成 Linux amd64 二进制: $OUTPUT"
