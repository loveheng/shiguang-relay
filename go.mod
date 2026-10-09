module shiguang-relay

go 1.26.0

// Phase 0 停火协议（fact-user-relay-draft §7.1-5）：本仓在契约冻结 tag 之前
// 不写任何 Go 业务代码；此文件仅用于固定 module 路径与 Go 版本，供
// Phase 1 `cmd/relayd` 与 proto 生成物（gen/go）直接落地。
// proto 生成的 go_package 与上面对应：shiguang-relay/gen/go;relayv1

require (
	github.com/alicebob/miniredis/v2 v2.39.0
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/jackc/pgx/v5 v5.11.0
	github.com/redis/go-redis/v9 v9.23.0
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/yuin/gopher-lua v1.1.1 // indirect
	go.uber.org/atomic v1.12.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.29.0 // indirect
)
