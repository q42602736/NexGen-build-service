#!/usr/bin/env bash

# 仅拦截 Worker 请求，普通下载和 GitHub 发布请求保持原有行为。
curl() {
  local argument
  for argument in "$@"; do
    case "$argument" in
      "${CF_WORKER_URL%/}"/*)
        node "$CF_WORKER_TOOLS/worker-request.mjs" "$@"
        return $?
        ;;
    esac
  done
  command curl "$@"
}
