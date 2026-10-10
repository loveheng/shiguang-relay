---
name: shiguang-relay-index
description: 时光中继（shiguang-relay）功能→代码/文档落点索引：鉴权/账号/好友/密钥托管/中继转发/同步等域级锚点。定位功能归属、找代码或文档落点时先查本表。
---

# shiguang-relay-index（功能 → 落点）

## 归属表

| 领域 | 覆盖功能 | 代码落点 | 文档落点 |
|---|---|---|---|
| 账号鉴权 | 注册(用户名+密码)/登录/刷新/改密/challenge/PoW/会话撤销/防爆破 | `internal/httpapi/router.go`、`internal/httpapi/register.go`；`internal/auth/`（password/token/pow/challenge/loginguard/epoch/denylist） | `docs/api/user-accounts.md`、`docs/architecture/accounts-e2ee-state.md`（现状与设计债） |
| 用户搜索 | 按用户名查公钥身份（加好友前置） | `internal/httpapi/register.go`（handleLookupUser） | `docs/api/user-accounts.md` |
| 密钥托管 | KeyBundle/OPK 分发与补仓（X3DH 素材） | `internal/httpapi/register.go`（prekey/refill）；`internal/store/`（prekeys） | — |
| 好友建联 | 扫码 Ticket 邀请 / 用户名直发申请 / 接受 / 列表 | `internal/httpapi/friends.go` | — |
| 密钥信封 | 参与方密钥信封存取（群/日程参与加密） | `internal/httpapi/`（vault/key-envelopes） | — |
| 日程同步 | 参与方发现 / 增量同步 / 日程动作 | `internal/httpapi/`（sync/schedule） | — |
| 消息中继 | 端到端密文中继收发/待取/ack | `internal/httpapi/`（relay） | — |
| WSS 通道 | WebSocket 长连接 hub、AUTH 帧、推送 | `internal/wss/` | — |
| 数据层 | PG schema / 各 store 仓储 | `schema.sql`；`internal/store/` | — |
| 部署 | Docker/Caddy/compose | `deploy/`、`Dockerfile`、`docker-compose*.yml` | — |

## 业务别名映射

- 用户名、密码、改密码、注册、登录 → 账号鉴权
- 搜索好友、找人 → 用户搜索
- 加好友、好友申请、扫码、名片、Ticket → 好友建联
- 预密钥、OPK、X3DH、KeyBundle → 密钥托管
- 转发、收消息、待取 → 消息中继
- 长连接、推送、在线 → WSS 通道

## 用法

先查表定位域 → 按代码落点展开（`ls internal/httpapi/`）或限定路径搜索 → 结果只用于当前任务，禁止写回索引 → 定位不到才全量搜索。

## 关联 skill

- 事实源（构建/测试命令/环境约束）：`shiguang-relay-workflow`
