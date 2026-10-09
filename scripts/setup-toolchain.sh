#!/usr/bin/env bash
# 安装 Phase 0.3 双端契约代码生成所需工具链：Go / protoc / protoc-gen-go / protoc-gen-dart
# 用法：bash scripts/setup-toolchain.sh   （全部装在 $HOME/sdk 与 $HOME/go，不碰系统目录、无需 root）
set -euo pipefail

SDK="${SDK:-$HOME/sdk}"
GO_VERSION="${GO_VERSION:-1.23.6}"
PROTOC_VERSION="${PROTOC_VERSION:-27.2}"
PROTOC_GEN_GO_VERSION="${PROTOC_GEN_GO_VERSION:-v1.34.2}"

mkdir -p "$SDK"

# 1) Go SDK（protoc-gen-go 构建 + Phase 1 服务端编译）
if [[ ! -x "$SDK/go$GO_VERSION/bin/go" ]]; then
  echo ">> 下载 Go $GO_VERSION"
  curl -sSL -o "$SDK/go.tgz" "https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz"
  tar -C "$SDK" -xzf "$SDK/go.tgz"
  rm -f "$SDK/go.tgz"
  mv -f "$SDK/go" "$SDK/go$GO_VERSION"
fi
export PATH="$SDK/go$GO_VERSION/bin:$PATH"
go version

# 2) protoc
if [[ ! -x "$SDK/protoc/bin/protoc" ]]; then
  echo ">> 下载 protoc $PROTOC_VERSION"
  mkdir -p "$SDK/protoc"
  curl -sSL -o "$SDK/protoc/p.zip" \
    "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip"
  if command -v unzip >/dev/null 2>&1; then
    unzip -o -q "$SDK/protoc/p.zip" -d "$SDK/protoc"
  else
    python3 -c "import zipfile;zipfile.ZipFile('$SDK/protoc/p.zip').extractall('$SDK/protoc')"
  fi
  rm -f "$SDK/protoc/p.zip"
  chmod +x "$SDK/protoc/bin/protoc"
fi
"$SDK/protoc/bin/protoc" --version

# 3) protoc-gen-go
export PATH="$HOME/go/bin:$PATH"
go install "google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOC_GEN_GO_VERSION}"
command -v protoc-gen-go

# 4) protoc-gen-dart（需要 Flutter 自带 dart：export PATH="$HOME/flutter/bin:$PATH"）
if ! command -v protoc-gen-dart >/dev/null 2>&1; then
  echo ">> 激活 protoc_plugin（需 dart 在 PATH）"
  dart pub global activate protoc_plugin
fi
export PATH="$HOME/.pub-cache/bin:$PATH"
command -v protoc-gen-dart

cat <<'TIP'

工具链就绪。后续常用 PATH（可写进 ~/.bashrc）：
  export PATH="$HOME/sdk/go1.23.6/bin:$HOME/sdk/protoc/bin:$HOME/go/bin:$HOME/.pub-cache/bin:$PATH"

生成双端契约：
  bash scripts/gen-proto.sh
TIP
