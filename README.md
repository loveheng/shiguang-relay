# shiguang-relay

拾光（ShiGuang）**盲中继服务端**——多人协同日程的「盲人代理」。

> 定位：服务端不接触任何业务明文，只做认证、路由、防骚扰、流程仲裁、密文暂存。
> 所有内容（日程标题/时间锚点/拒绝理由/备注）在出设备前 E2EE 加密。
> 设计 SSOT：`docs/design/collab-schedule-draft.md` 与 `collab-implementation.md`。

## 本仓边界（§8.4）

- **独立新仓**，不进拾光主仓、不做 Monorepo；物理隔离杜绝客户端明文模型类被导入服务端。
- 协议：**Protocol Buffers**（`relay_protocol.proto` 单一事实源）→ Go 出 `types.pb.go`、Flutter 出 `types.pb.dart`，CI 校验生成产物同步。
- 与 `mcp_server`/`mcp_controller`（给桌面 AI、JSON-RPC/stdio）**协议不同、物理分仓**。

## Phase 0 冻结契约（2026-10-09 用户拍板）

| 文件 | 内容 |
|---|---|
| `relay_protocol.proto` | 信封 / action 枚举 / 拓扑骨架 / 密钥通道 / FreeMask / 鉴权 / 好友 Ticket / WakePush |
| `schema.sql` | 10 表 PG DDL（users / prekeys / friendships / storage / bundles / skeletons / cursors / events / key_envelopes / relay_messages） |

> **停火协议**：拍板后 Phase 0 只交付上述两个契约文件并打 tag，**不写一行 Go 业务代码**；契约锁死后再铺后续 Phase。

## 已拍板的地基转向与默认值

- **§13 修正（Q9）**：守 `零代发` + `内容 E2EE`，放开 `多机同步 / 外部账号 / 服务端联系人`；产品灵魂四项（连胜打卡/无限层级树/手环同步/社交分享排行榜）**永久不变**。
- **Q1**：社交图暂不 E2E；`friendships` 严格只 4 列（a,b,status,created_at），无 nickname/phone 明文。
- **Q2**：匿名 token + PoP 自签注册，无邮箱/手机。
- **Q3**：手动白名单 + 仅双向 accepted 好友。
- **Q5**：门限共识（M-of-N）+ 发起人落槌 `FORCE_FINALIZE`。
- **Q7**：MSK 本地安全存储 + `recovery_vault` 增量信封（WebDAV/R2 备份）。
- **Q8**：自建 VPS + Docker Compose + Caddy 反代；push 走 FCM/APNs。
- **Q10**：本仓 = 独立中继，不复用 MCP 桥。

## 三项工程防线（并入实现计划对应 Phase）

1. **Sybil / 存储轰炸（Phase 1.2）**：注册 PoW / Hashcash（SHA-256 前导 4×0）+ 单 IP ≤3–5 账号/分钟。
2. **灾备死穴（Phase 1.7/5）**：`docker-compose.yml` 捆绑 Litestream / 定时 `pg_dump` sidecar，每小时异地备份至 Cloudflare R2/S3。
3. **FCM/APNs 阻塞（Phase 1.6/1.7）**：异步 Worker 池（内存 `chan PushTask` + 2–3 goroutine），主事务写 PG + WSS 广播后即返回 200，离线 Push 异步消费。

## 目录（规划，Phase 1+ 才落）

```
shiguang-relay/
├── Dockerfile / docker-compose.yml   # 联调 PG/Redis + 备份 sidecar
├── relay_protocol.proto              # ✅ Phase 0 已冻结
├── schema.sql                        # ✅ Phase 0 已冻结
├── main.go
├── handler/  hub/  fsm/  queue/
└── gen/  (types.pb.go / types.pb.dart 生成产物)
```
