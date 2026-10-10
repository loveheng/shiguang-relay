---
name: shiguang-relay-workflow
description: 时光中继（shiguang-relay）事实源：Go 1.26 盲状态机 E2EE 中继，模块结构、构建/测试/proto 重生成命令与环境硬约束。构建、测试、改契约、装配依赖前必读。
---

# shiguang-relay workflow（事实源）

## 技术栈与环境硬约束

- Go 服务（module `shiguang-relay`），`go.mod` 声明 `go 1.26.0`。**SDK 目录名有误导**：实际 Go 1.26.0 在 `~/sdk/go1.23.6/bin`（目录名 ≠ 版本），PATH 必须先加它。
- proto 工具链：`protoc` 在 `~/sdk/protoc/bin`，插件 `protoc-gen-go`/`protoc-gen-dart` 在 PATH（`scripts/gen-proto.sh` 一键重生成 gen/go + gen/dart）。
- 存储：PostgreSQL（schema.sql 建库）+ Redis（幂等/限流/challenge）。`*_pg_test.go` 需真 PG，无 DB 时相关用例跳过。
- 密码哈希零外部依赖：用**标准库自建 PBKDF2-HMAC-SHA256**（`internal/auth/password.go`），勿引入新的第三方密码学包。

## 模块结构

```
cmd/relayd/        唯一入口 main.go（装配 Deps）
internal/httpapi/  REST API（router.go 全路由 + register/friends/token 等 handler）
internal/wss/      WebSocket hub（AUTH 走 JSON 帧 {"action":"AUTH","token":...}，不用 proto LoginRequest）
internal/auth/     认证原语：password(PBKDF2)/token(JWT pair)/pop/pow/challenge/resolver/limiter
internal/store/    PG 访问层（users/prekeys/friendships/...），单事务约束「有用户必有密钥」
internal/apierr/   统一错误码（错误通道零明文红线）
internal/config/   配置装载
gen/go, gen/dart   proto 生成产物（勿手改，改 relay_protocol.proto 后跑 scripts/gen-proto.sh）
schema.sql         PG 建库事实源（列约束/唯一键以此为准）
deploy/            Caddyfile 等部署配置；docker-compose.yml / Dockerfile
```

## 命令（均已实测跑通）

```bash
export PATH="$HOME/sdk/go1.23.6/bin:$HOME/sdk/protoc/bin:$HOME/go/bin:$PATH"
go build ./...          # 编译
go vet ./internal/... ./cmd/...   # 静态检查（含测试文件编译）
go test ./internal/auth/          # 无 DB 依赖的纯单测
go test ./...                     # 全量；*_pg_test 需 PG，无 DB 自动跳过
bash scripts/gen-proto.sh         # 改 relay_protocol.proto 后重生成双端契约
```

## 架构铁律（改代码前必读）

- 盲状态机 E2EE：服务端只存公钥与密文，`identity_key_pub`/`signed_prekey_pub`/OPK 池是**加密引擎**不是登录凭证。
- 身份模型 Plan A：`username`（小写 3~32，`[a-z0-9_]`）+ 密码哈希仅做账号鉴权；E2EE 密钥端侧持有，对用户透明。
- 注册/登录错误响应口径：用户不存在与密码错误同一响应（防账号枚举）。
- user_id 由服务端 `gen_random_uuid()` 生成（客户端不再自报 UUID）。
