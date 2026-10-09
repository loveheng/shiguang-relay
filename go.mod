module shiguang-relay

go 1.23

// Phase 0 停火协议（fact-user-relay-draft §7.1-5）：本仓在契约冻结 tag 之前
// 不写任何 Go 业务代码；此文件仅用于固定 module 路径与 Go 版本，供
// Phase 1 `cmd/relayd` 与 proto 生成物（gen/go）直接落地。
// proto 生成的 go_package 与上面对应：shiguang-relay/gen/go;relayv1

require google.golang.org/protobuf v1.36.12
