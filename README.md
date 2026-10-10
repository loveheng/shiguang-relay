# shiguang-relay

拾光（shiguang）多人协同的**中继服务端**：独立 Go 仓，盲状态机中继（内容纯 E2EE、零事实明文）。

> 设计 SSOT：`docs/design/schedule-app.md`；协同设计：`docs/design/collab-schedule-draft.md` 与 `docs/design/fact-user-relay-draft.md`；施工表：`docs/design/collab-implementation.md`。
> **双仓边界**：本仓不 import 拾光任何代码；拾光主仓（`shiguang`）只增不破坏。两仓同级存放，不互相嵌套。

## 本仓内容

| 路径 | 作用 |
|---|---|
| `relay_protocol.proto` | 全部消息信封、ActionType 枚举、鉴权/好友/密钥/瞬时信令协议（契约源头，双端代码由它生成） |
| `schema.sql` | PostgreSQL DDL **唯一出处**（全量 10 表：底座 `users`/`friendships`/`key_envelopes` OPK 池/`relay_messages` + 协同 `bundles`/`bundle_skeletons`/`bundle_members`/`bundle_member_cursors`/`team_schedule_events`/`user_key_envelopes`） |
| `gen/go/`、`gen/dart/` | 由 proto 生成的**只读**契约代码（入仓；CI 校验同步，见 `scripts/check-proto-sync.sh`） |
| `Dockerfile` / `docker-compose.yml` | 镜像骨架 + 本地 PG/Redis 底座（`relay` 服务在 `profiles: [app]`，Phase 1 起用） |
| `scripts/` | `setup-toolchain.sh`（装 Go/protoc/插件）· `gen-proto.sh`（双端生成）· `check-proto-sync.sh`（CI）· `verify-phase0.sh`（建库 + seq 约束验收） |

> Phase 0 停火协议（`fact-user-relay-draft.md §7.1-5`）：契约冻结 tag 之前**不写一行 Go 业务代码**；`cmd/relayd` 属 Phase 1。

## 快速开始

```bash
# 1) 工具链（装进 ~/sdk 与 ~/go，无需 root）
bash scripts/setup-toolchain.sh

# 2) 生成双端契约代码
bash scripts/gen-proto.sh

# 3) 起 PG/Redis（podman-compose）并验收 DDL + seq 唯一约束（Phase 0 退出条件）
bash scripts/verify-phase0.sh          # 默认 podman-compose；要用 docker compose：COMPOSE="docker compose" bash scripts/verify-phase0.sh

# 4) Phase 1 冒烟：真 PG/Redis + 真 relayd 进程，验鉴权闭环与幂等去重
bash scripts/smoke-phase1.sh

# 5) 单测（miniredis，无需真 Redis）
go test ./...
```

日常起停（本机 podman-compose）：

```bash
podman-compose up -d                   # PG + Redis
podman-compose --profile app up -d     # 含 relay 服务（Phase 1 起）
podman-compose down
```

常用 PATH（可写进 `~/.bashrc`）：

```bash
export PATH="$HOME/sdk/go1.23.6/bin:$HOME/sdk/protoc/bin:$HOME/go/bin:$HOME/.pub-cache/bin:$PATH"
```

## 当前进度

- **Phase 0 契约冻结：已完成**（tag `v0.1.6-contract`，零 Go 业务代码）。
- **Phase 1.1 鉴权闭环：已完成**——`POST /v1/auth/challenge` / `login` / `refresh` + Bearer 鉴权（401）+ `client_msg_id` 幂等去重（300s 窗口内重放原样回放）。REST 侧两个外层头：`X-Client-Msg-Id`、`X-Client-Ts`（WSS 侧走 proto `ClientFrame.client_msg_id/client_ts`，同语义）。
- **Phase 1.2 注册与 PreKey 托管：已完成**——`POST /v1/users`（PoP 自签 + PoW + 单 IP 限流 3/min + OPK 首批 10~20，单事务落用户与密钥）、`GET /v1/users/{id}/prekey`（身份包 + `FOR UPDATE SKIP LOCKED` 原子弹出 1 个 OPK，空池恒 200 带 `OPK_EMPTY_WARNING`）、`POST /v1/users/me/prekeys`（鉴权后补仓 ≤50/批）。
- **Phase 1.3 好友域：已完成**——`POST /v1/friends/invite {ticket, encrypted_intro}`（Ticket 规范化消息 Ed25519 验签 + 过期 + nonce 一次性 `SETNX` + 待审批配额 ≤50 + 关系去重 409）、`POST /v1/friends/accept {invite_id, accept}`（**仅被邀方**可处置，accept=false → blocked，intro 随即置 NULL）、`GET /v1/friends`（`encrypted_intro` 只在「我是被邀方 + 仍 pending」时回包）。Ticket 签名覆盖范围：`shiguang.relay.v1/friendship-ticket|<issuer>|<subject>|<nonce>|<expires_at>`（双端一字不能差）。
- **Phase 1.4 协同动作：已完成**——`POST /v1/schedule/action`：`PROPOSE` 建包（准入严管=发起人与每个被邀请人双向 accepted + 成员 ≤16 + 活跃包 ≤20，单事务落 bundles/skeletons/成员信封/seq:1 事件）；其他动作走**成员 ACL**（包内放行，不要求 B↔C 互为好友）+ `UPDATE bundles ... RETURNING max_seq_id` **行锁取号**（§5.1，杜绝 MAX+1 同号冲突）+ 单事务落流水；事实三动作（`ATTACH_FACT`/`UPDATE_FACT`/`DETACH_FACT`）**绕过 `base_revision` 乐观锁**只取 seq；`FORCE_FINALIZE` 落槌 CONFIRMED，敲定后一切动作 409；广播接口 `Broadcaster` 已立，1.6 换 WSS Hub（当前 Noop）。
- **Phase 1.5 发现与同步：已完成**——换机冷启动链路全通：`GET /v1/bundles/participating?status=active`（参与中包 + `max_seq_id` + `last_acked_seq`）→ `GET /v1/schedule/sync?bundle_id=&since_seq=&limit=`（增量补拉/跳号补洞，成员 ACL + 单页 ≤500）→ `GET /v1/bundles/{id}/key-envelopes`（**只回本成员**信封）+ `POST/GET /v1/vault/envelopes`（MSK 封送的 K_bundle 增量信封，Append-Only 同版本幂等，绝不 LWW 覆盖）；瞬时信令 `POST /v1/relay/msg`（**双向好友 ACL**）→ `GET /v1/relay/pending` → `POST /v1/relay/ack`（先置 acked 再物理 DELETE，阅后即焚）。
- **Phase 1.6 WSS Hub：已完成**——`GET /ws` **纯路径建连**（token 绝不进 URL，防反代 Access Log 泄露凭证）→ **首帧必须是 `{"action":"AUTH","token":...}`，3s 内未完成即掐线**（非法 token 立即关闭）→ 其后一律 **protobuf 二进制帧**（`ServerFrame`/`ClientFrame`，复用冻结契约而非另立编码约定）；`CLIENT_ACK` 落 `bundle_member_cursors`（`GREATEST` 单调推进）；`Hub` 已接替 `NoopBroadcaster` 成为事件广播器——在线成员直推、离线成员交 `WakePusher`（接口已立，1.7 实装 FCM/APNs）。
- **Phase 1.7 部署 + 1.8 网关收尾：已完成**——`deploy/Caddyfile`（WSS Upgrade 透传 / 256KB 硬限 / 日志过滤 query 与 Authorization / healthz 由反代应答）、`docker-compose.prod.yml`（PG 卷持久化 + Redis + relay + Caddy + **每小时 `pg_dump|gzip` 备份 sidecar**）、`scripts/backup.sh`、`scripts/ops-cleanup.sh`（TTL 清理 + 磁盘水位告警）、`.env.example`；`/v1/healthz` 升级为**真探针**（PG/Redis 任一不可达 503）；错误码字典已入 README。**Phase 1 服务端最小闭环（1.1–1.8）全通**，下一步 Phase 2 才碰拾光主仓。
- **账号体系（Plan A）：已完成**——用户名+密码注册/登录/改密（`POST /v1/users` · `POST /v1/auth/login` · `POST /v1/auth/change-password`，PBKDF2 哈希零明文）+ 用户名搜索加好友（`GET /v1/users/lookup`）+ 扫码 Ticket 双通道并存；`users` 表加 `username`(唯一)/`password_hash` 列；E2EE 密钥体系藏于其后，对用户全程透明。

## 鉴权与账号体系（Plan A：用户名+密码，密钥对用户透明）

- **注册**：`POST /v1/users` 携 `username`（小写字母/数字/下划线 3~32，唯一）+ `password`（≥8 位，服务端 PBKDF2-HMAC-SHA256 派生哈希，零明文落库）+ E2EE 公钥材料（身份钥/签名预钥/首批 OPK 10~20）。保留 PoW + 单 IP 限流防女巫。
- **登录**：`POST /v1/auth/login {username, password}` 验哈希签双 Token（access 短效 / refresh 长效，`POST /v1/auth/refresh` 续期）；用户不存在与密码错误同一 401 口径（防账号枚举）。
- **改密**：`POST /v1/auth/change-password {old_password, new_password}`（Bearer）——仅换哈希不动端侧 E2EE 密钥；换设备走 `recovery_vault` 恢复密钥。
- **加好友双通道**：搜索 `GET /v1/users/lookup?username=`（Bearer，限流防枚举）→ `POST /v1/friends/request {to_user_id, encrypted_intro}` 直发；扫码原 `POST /v1/friends/invite {ticket, encrypted_intro}` 不变。两路同样落 pending、被邀方手动 approve，`GET /v1/friends` 回包携带对方 `username`。
- **密钥体系对用户透明**：E2EE（Ed25519 IK + X25519 SPK + OPK）是加密引擎而非登录凭证，用户全程只见「用户名+密码」。
- **WSS 首帧 AUTH**：连接后 3s 内必须发 `{"action":"AUTH","token":...}`，否则掐线；后续帧按 `client_msg_id` 去重。
- **重放去重键**：`client_msg_id` + `client_ts`，服务端 Redis `SETEX 300` 幂等；同键重放返回首次结果，不入流水。
- **网关硬约束**：单包 Payload ≤256KB；P2P 瞬时信令 `relay_messages` TTL 即焚（`status='acked'` 即物理删 + 过期清理 cron）。

## 2026-10-09 审查修正要点（已内建）

1. **废除独立 Mailbox API**：事实同步并入 bundle 事件流（`ATTACH_FACT` / `UPDATE_FACT` / `DETACH_FACT`），与排程共用全局 `seq_id` 与 WSS 广播。
2. **零明文昵称**：注册/好友接口剔除 `display_name`；昵称/备注仅存 `encrypted_profile`（端侧全密文）。`friendships` 仅 5 列（v0.1.3 起 pending 期留存 `encrypted_intro`）。
3. **零 `entity_key` 暴露**：服务端不接收/不存储任何业务代号（车次、预约码）。事实级去重由**客户端 resolver（纯本地）**解密后完成；传输级去重由 `client_msg_id` 幂等保证。
4. **好友 Ticket 制**：`POST /v1/friends/invite {ticket, encrypted_intro}` 替代 `{to_user}`，防全库遍历撞库；`encrypted_intro` 为 A 用 Ticket 内 B 的 X25519 加密公钥（`enc_key_pub`=signed_prekey_pub）做 ECIES 加密的自报家门（解纯 UUID 审批死锁，pending 期落盘、`GET /v1/friends` 回包携带）。
5. **双 Token + 重放防护**：见上节；`client_msg_id` + 时间戳 Redis `SETEX 300` 去重。
6. **网关硬约束**：单包 Payload **≤256KB**；P2P 瞬时信令 `relay_messages` **TTL 即焚** + 后台清理 cron。

## 部署（Phase 1.7）

```bash
cp .env.example .env                 # 至少设置 RELAY_JWT_SECRET（≥32 字节）与 RELAY_DOMAIN
podman-compose -f docker-compose.prod.yml up -d
```

- `deploy/Caddyfile`：TLS 自动签发；`/ws` 放行 Upgrade 头（否则 WSS 握手被反代吃掉）；请求体硬限 256KB；**日志过滤 query 与 Authorization**（token 绝不进 URL 的底线不能在日志里破功）；`/v1/healthz` 由反代直接应答，不透传。
- `docker-compose.prod.yml`：`postgres`（卷持久化 + 健康门）/`redis`/`relay`/`caddy` + **`backup` sidecar**（每小时 `pg_dump | gzip`，保留 7 天，配 `RCLONE_REMOTE` 即异地同步）——守住「单机 VPS 炸了 10 分钟内拉起新主机一键还原」底线。
- 灾备手工触发：`podman-compose -f docker-compose.prod.yml exec -T backup /backup.sh`。

## 运维收尾（Phase 1.8）

```bash
# 建议宿主 cron：*/30 * * * * .../scripts/ops-cleanup.sh
COMPOSE="podman-compose -f docker-compose.prod.yml" bash scripts/ops-cleanup.sh
```

- 瞬时信令 TTL 清理（`status='acked'` 或 `expires_at < now()` 即物理删除）；
- 磁盘水位告警（默认 ≥85% 退出码 1，接监控系统即可告警）；
- `/v1/healthz` 为**真探针**：PG/Redis 任一不可达即 503（不返回任何内部细节）。

## 错误码字典（§10.4，统一响应体）

```json
{ "error_code": "STALE_REVISION", "message": "base revision conflict", "detail": { } }
```

| error_code | HTTP | 场景 |
|---|---|---|
| `INVALID_REQUEST` | 400 | 请求体畸形 / 缺 `X-Client-Msg-Id` / 时间戳超窗 |
| `UNAUTHORIZED` | 401 | 无或无效的 access_token（不细分原因，避免反馈面） |
| `CHALLENGE_INVALID` | 401 | nonce 未知/过期/已用 |
| `POP_SIGNATURE_INVALID` | 401 | 所有权证明签名不匹配（含公钥置换攻击） |
| `POW_SOLUTION_INVALID` | 401 | Hashcash 解错误 |
| `TICKET_EXPIRED` / `TICKET_SIGNATURE_INVALID` | 400 / 401 | 好友名片失效 / 被篡改 |
| `TICKET_NONCE_USED` / `TICKET_SUBJECT_INVALID` | 400 / 403 | 名片 nonce 重放 / 扫码者非指定人 |
| `RECIPIENT_NOT_FRIEND` / `RELATION_TERMINATED` | 403 | 非双向好友直投 / 关系已终止 |
| `NOT_PARTICIPANT` / `NOT_INITIATOR` | 403 | 非方案包成员 / 非发起人操作专属动作 |
| `BUNDLE_NOT_FOUND` / `USER_NOT_FOUND` / `INVITE_NOT_FOUND` | 404 | 资源不存在 |
| `USER_ALREADY_EXISTS` / `RELATION_EXISTS` | 409 | 重复注册 / 关系已存在 |
| `USERNAME_INVALID` / `USERNAME_EXISTS` | 400 / 409 | 用户名不合法（3~32 小写字母/数字/下划线）/ 已被占用 |
| `PASSWORD_TOO_WEAK` | 400 | 密码强度不足（<8 位） |
| `USER_OR_PASSWORD_INVALID` | 401 | 用户名或密码错误（不区分，防账号枚举） |
| `PASSWORD_MISMATCH` | 401 | 改密时旧密码错误 |
| `BUNDLE_CONFIRMED_IMMUTABLE` | 409 | 方案包已敲定/取消/过期 |
| `STALE_REVISION` | 409 | 因果冲突（事实三动作豁免） |
| `EXCEED_MAX_MEMBERS` / `EXCEED_ACTIVE_BUNDLES` / `EVENT_QUOTA_EXCEEDED` / `EXCEED_PENDING_INVITES` | 400 | 防爆仓配额族 |
| `PREKEY_COUNT_INVALID` | 400 | OPK 数量越界（首批 10~20 / 补仓 ≤50） |
| `RATE_LIMITED` | 429 | 注册或邀请限流 |
| `ATTACHMENT_OVERSIZE` | 413 | 单包超 256KB |
| `UNKNOWN_ACTION` | 400 | 未登记的 action_type |
| `INTERNAL_ERROR` | 500 | 服务端内部错误（细节只进日志） |

> 零明文红线：`message` 恒为服务端固定英文串，`detail` 只放 UUID/seq 等结构值——错误通道同样过零知识审计。

## 契约版本

- `v0.1.0-contract`：首版冻结（含服务端架构审查修正：废 mailbox、零明文、零 entity_key、Ticket 防撞库、双 Token、256KB/TTL）。
- `v0.1.1-contract`（2026-10-09 补丁）：加好友自报家门（`encrypted_intro` 解审批死锁）、`ATTACH_FACT` 语义定调（FSM 零影响 + 平权）、OPK 注册瘦身（10~20）、§1.7 ACL 摘掉好友分支、Q12 事实所有权本地化。Phase 1 起按此实现。
- `v0.1.2-contract`（2026-10-09 补丁）：Artifact 契约加性字段 `target_step_ref`（可选，指向 bundle step_uid，CONFIRMED 下沉时精准回填 block）；本地 artifacts 加 `bundle_id` 弱引用列（协商期 `plan_id=NULL`）+ 反转块-凭证关联（`blocks.artifact_id` 替代 `artifacts.block_id`）；临场时相公式去 2×2 特判（统一 `T_target=T_action−(advance??0)`、`T_dismiss=T_action+20min`）；移动在途允许端侧最小确定性模板抽取器（受控例外，非 AI 推理）。**服务端 envelope 零结构变更**（事实仍在 cipher 内）。
- `v0.1.3-contract`（2026-10-09 补丁，加性向后兼容）：补齐 4 处接口契约断层——①瞬时信令 `GET /v1/relay/pending` + `POST /v1/relay/ack {message_ids}`（阅后即焚，relay_messages.status='acked' 即物理删；在线由 WSS 直推）；②加好友 `encrypted_intro` 落盘（`friendships.encrypted_intro` + `FriendshipView` 回包携带，解纯 UUID 审批死锁）；③密钥增量金库 `user_key_envelopes` 表 + `POST/GET /v1/vault/envelopes`（换机 100% 还原历史 K_bundle）；④`ATTACH_FACT`/`UPDATE_FACT`/`DETACH_FACT` 显式绕过 `base_revision` 乐观锁，仅原子自增 `max_seq_id`（防假性冲突惊群）。**本轮服务端 DDL 确有新增**（`user_key_envelopes` 表 + `friendships.encrypted_intro` 列）。
- `v0.1.4-contract`（2026-10-09 补丁，加性向后兼容）：①X3DH 生命周期两端点 `GET /v1/users/{id}/prekey`（拉 KeyBundle + 服务端原子弹出 1 个 OPK）+ `POST /v1/users/me/prekeys`（OPK 低位补仓）；②`GET /v1/bundles/participating` 归位 fact §5.2 清单（换机冷启动第一步）；③DDL 补 `bundle_member_cursors` 游标表，**全量 9 表定盘**（4 底座 + 5 协同）；④密码学错配修正：`FriendshipTicket` 改携 B 的 X25519 加密公钥（`enc_key_pub`=signed_prekey_pub），ECIES 不再误用 Ed25519 身份签名钥；⑤`bundles` 列集与协同 §10.1 合流（FSM `status` + 存储 `lifecycle` 双列，`proposal_type`/`base_revision`/`participant_uids`/`expires_at` 并入 + GIN 索引），`bundle_skeletons.topology` JSONB 内部结构定盘步骤级仲裁字段，`schema.sql` 自此为服务端 DDL 唯一出处。
- `v0.1.5-contract`（2026-10-09 补丁，加性向后兼容）：团队 E2EE 总纲定盘（collab §5.3.1）——①`Envelope` 补明文外层 `key_ver` + `member_key_envelopes` 字段与 `MemberKeyEnvelope` 消息（收口「解密前无从选钥」缺口）；②新增 `ADD_MEMBER` 动作（中途加人：现役 key_ver 不变、仅追加新人信封、零 REKEY、可看全量历史）；③新增 `bundle_members` 信封落表（第 10 表）+ `GET /v1/bundles/{id}/key-envelopes` 补拉端点；④密钥保留口径修正：K_bundle 保留至 bundle 生命周期终（金库信封长期留存），废「敲定即销毁」表述。
- `v0.1.6-contract`（2026-10-09 补丁，零字段/零 DDL 行为契约）：①time_anchors 可选 `tz`/`end_tz` 时区锚（cipher 内，缺省本地墙钟零迁移；跨时区行程先折算绝对时刻再运算）；②OPK 空池降级：prekey 恒 200、OPK 空即端侧 4-DH→3-DH（Signal 标准）+ 静默补仓通知；③Wake Push 零知识载荷规范（APNs `content-available`/FCM 纯 data，零明文、本地发声）；④防爆仓硬配额（成员≤16/活跃包≤20/流水≤2000/待审批邀请≤50）；⑤Bundle 终态（CANCELLED/EXPIRED）凭证脱钩转正未归属池（绝不物理删除）；⑥全局错误码字典 + 零明文红线（collab §10.4）。
- **Phase 0 工程产物（本轮新增，非协议变更）**：仓骨架 `go.mod`/`Dockerfile`/`docker-compose.yml`、生成与验收脚本 `scripts/`、proto 补 `go_package` 选项、`schema.sql` 校准（DDL 唯一出处）。
