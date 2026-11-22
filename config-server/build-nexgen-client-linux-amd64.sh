#!/bin/sh

set -eu
umask 077

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

mkdir -p dist
chmod 700 dist

OUTPUT="dist/nexgen-client"
TMP_OUTPUT="${OUTPUT}.tmp"
CONFIG_PATH=${NEXGEN_EMBED_CONFIG:-"$SCRIPT_DIR/.env"}
GARBLE_BIN=${GARBLE_BIN:-garble}

if [ ! -f "$CONFIG_PATH" ]; then
  echo "未找到本地 .env；请在 config-server/.env 填写私有配置并设置权限 0600" >&2
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

go run ./cmd/embed-config "$CONFIG_PATH" "$WORK_DIR" "$SCRIPT_DIR"

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
