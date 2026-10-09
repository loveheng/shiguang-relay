#!/usr/bin/env bash
# CI 检查：relay_protocol.proto 与 gen/ 下的双端生成物是否同步（改动契约未重生成即拦截）
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/sdk/go1.23.6/bin:${HOME}/sdk/protoc/bin:${HOME}/go/bin:${HOME}/.pub-cache/bin:${HOME}/flutter/bin:${PATH}"

command -v protoc >/dev/null || { echo "缺 protoc，先跑 scripts/setup-toolchain.sh"; exit 1; }

OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
mkdir -p "$OUT/go" "$OUT/dart"

protoc -I "$ROOT" \
  --go_out="$OUT/go"   --go_opt=paths=source_relative \
  --dart_out="$OUT/dart" \
  "$ROOT/relay_protocol.proto"

if diff -r "$OUT/go" "$ROOT/gen/go" >/dev/null && diff -r "$OUT/dart" "$ROOT/gen/dart" >/dev/null; then
  echo "proto-sync: OK（双端生成物与契约一致）"
else
  echo "proto-sync: FAIL —— 契约已改但生成物未同步，请跑 scripts/gen-proto.sh 后一并提交"
  diff -r "$OUT/go" "$ROOT/gen/go" || true
  diff -r "$OUT/dart" "$ROOT/gen/dart" || true
  exit 1
fi
