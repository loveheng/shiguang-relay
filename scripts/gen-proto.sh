#!/usr/bin/env bash
# 生成双端只读契约代码：gen/go/relay_protocol.pb.go + gen/dart/relay_protocol.pb.dart
# 契约改动后必跑；生成物入仓（CI 用 check-proto-sync.sh 校验同步）
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# protoc-gen-dart 是调用 dart 的 shell 包装，flutter/bin 必须在 PATH 内
export PATH="${HOME}/sdk/go1.23.6/bin:${HOME}/sdk/protoc/bin:${HOME}/go/bin:${HOME}/.pub-cache/bin:${HOME}/flutter/bin:${PATH}"

command -v protoc           >/dev/null || { echo "缺 protoc，先跑 scripts/setup-toolchain.sh"; exit 1; }
command -v protoc-gen-go    >/dev/null || { echo "缺 protoc-gen-go，先跑 scripts/setup-toolchain.sh"; exit 1; }
command -v protoc-gen-dart  >/dev/null || { echo "缺 protoc-gen-dart，先跑 scripts/setup-toolchain.sh"; exit 1; }

mkdir -p "$ROOT/gen/go" "$ROOT/gen/dart"

protoc -I "$ROOT" \
  --go_out="$ROOT/gen/go"   --go_opt=paths=source_relative \
  --dart_out="$ROOT/gen/dart" \
  "$ROOT/relay_protocol.proto"

echo "生成完成："
ls -1 "$ROOT/gen/go" "$ROOT/gen/dart"
