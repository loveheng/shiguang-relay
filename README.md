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
- **未开工**：1.5 participating/sync/vault/relay pending-ack、1.6 WSS hub、1.7 部署、1.8 网关硬约束（256KB 已随 decode 生效；TTL 清理 cron / 错误码字典补全待做）。

## 鉴权与重放防护（契约定稿摘要，Phase 0.5）

- **Challenge-Response**：`POST /v1/auth/challenge` 下发 `nonce` + `pow_challenge/difficulty`（Hashcash，仅挡最低级扫描；真防线=注册孤岛无害化 + 单 IP ≤3/min + OPK 瘦身）；客户端回 `signed_pop`（Ed25519 对 nonce 签名）+ `pow_solution`，服务端校验后签双 Token（access 短效 / refresh 长效，`POST /v1/auth/refresh` 续期）。
- **注册**：开放匿名 PoP 自签（`POST /v1/users`），**无邀请制**（防冷启动死锁）、无邮箱/手机；`encrypted_profile` 端侧全密文，服务端零明文昵称。
- **WSS 首帧 AUTH**：连接后 3s 内必须发 `ClientFrame{auth: AuthChallenge/LoginRequest}` 完成鉴权，否则掐线；后续帧按 `client_msg_id` 去重。
- **重放去重键**：`client_msg_id` + `client_ts`，服务端 Redis `SETEX 300` 幂等；同键重放返回首次结果，不入流水。
- **网关硬约束**：单包 Payload ≤256KB；P2P 瞬时信令 `relay_messages` TTL 即焚（`status='acked'` 即物理删 + 过期清理 cron）。

## 2026-10-09 审查修正要点（已内建）

1. **废除独立 Mailbox API**：事实同步并入 bundle 事件流（`ATTACH_FACT` / `UPDATE_FACT` / `DETACH_FACT`），与排程共用全局 `seq_id` 与 WSS 广播。
2. **零明文昵称**：注册/好友接口剔除 `display_name`；昵称/备注仅存 `encrypted_profile`（端侧全密文）。`friendships` 仅 5 列（v0.1.3 起 pending 期留存 `encrypted_intro`）。
3. **零 `entity_key` 暴露**：服务端不接收/不存储任何业务代号（车次、预约码）。事实级去重由**客户端 resolver（纯本地）**解密后完成；传输级去重由 `client_msg_id` 幂等保证。
4. **好友 Ticket 制**：`POST /v1/friends/invite {ticket, encrypted_intro}` 替代 `{to_user}`，防全库遍历撞库；`encrypted_intro` 为 A 用 Ticket 内 B 的 X25519 加密公钥（`enc_key_pub`=signed_prekey_pub）做 ECIES 加密的自报家门（解纯 UUID 审批死锁，pending 期落盘、`GET /v1/friends` 回包携带）。
5. **双 Token + 重放防护**：见上节；`client_msg_id` + 时间戳 Redis `SETEX 300` 去重。
6. **网关硬约束**：单包 Payload **≤256KB**；P2P 瞬时信令 `relay_messages` **TTL 即焚** + 后台清理 cron。

## 契约版本

- `v0.1.0-contract`：首版冻结（含服务端架构审查修正：废 mailbox、零明文、零 entity_key、Ticket 防撞库、双 Token、256KB/TTL）。
- `v0.1.1-contract`（2026-10-09 补丁）：加好友自报家门（`encrypted_intro` 解审批死锁）、`ATTACH_FACT` 语义定调（FSM 零影响 + 平权）、OPK 注册瘦身（10~20）、§1.7 ACL 摘掉好友分支、Q12 事实所有权本地化。Phase 1 起按此实现。
- `v0.1.2-contract`（2026-10-09 补丁）：Artifact 契约加性字段 `target_step_ref`（可选，指向 bundle step_uid，CONFIRMED 下沉时精准回填 block）；本地 artifacts 加 `bundle_id` 弱引用列（协商期 `plan_id=NULL`）+ 反转块-凭证关联（`blocks.artifact_id` 替代 `artifacts.block_id`）；临场时相公式去 2×2 特判（统一 `T_target=T_action−(advance??0)`、`T_dismiss=T_action+20min`）；移动在途允许端侧最小确定性模板抽取器（受控例外，非 AI 推理）。**服务端 envelope 零结构变更**（事实仍在 cipher 内）。
- `v0.1.3-contract`（2026-10-09 补丁，加性向后兼容）：补齐 4 处接口契约断层——①瞬时信令 `GET /v1/relay/pending` + `POST /v1/relay/ack {message_ids}`（阅后即焚，relay_messages.status='acked' 即物理删；在线由 WSS 直推）；②加好友 `encrypted_intro` 落盘（`friendships.encrypted_intro` + `FriendshipView` 回包携带，解纯 UUID 审批死锁）；③密钥增量金库 `user_key_envelopes` 表 + `POST/GET /v1/vault/envelopes`（换机 100% 还原历史 K_bundle）；④`ATTACH_FACT`/`UPDATE_FACT`/`DETACH_FACT` 显式绕过 `base_revision` 乐观锁，仅原子自增 `max_seq_id`（防假性冲突惊群）。**本轮服务端 DDL 确有新增**（`user_key_envelopes` 表 + `friendships.encrypted_intro` 列）。
- `v0.1.4-contract`（2026-10-09 补丁，加性向后兼容）：①X3DH 生命周期两端点 `GET /v1/users/{id}/prekey`（拉 KeyBundle + 服务端原子弹出 1 个 OPK）+ `POST /v1/users/me/prekeys`（OPK 低位补仓）；②`GET /v1/bundles/participating` 归位 fact §5.2 清单（换机冷启动第一步）；③DDL 补 `bundle_member_cursors` 游标表，**全量 9 表定盘**（4 底座 + 5 协同）；④密码学错配修正：`FriendshipTicket` 改携 B 的 X25519 加密公钥（`enc_key_pub`=signed_prekey_pub），ECIES 不再误用 Ed25519 身份签名钥；⑤`bundles` 列集与协同 §10.1 合流（FSM `status` + 存储 `lifecycle` 双列，`proposal_type`/`base_revision`/`participant_uids`/`expires_at` 并入 + GIN 索引），`bundle_skeletons.topology` JSONB 内部结构定盘步骤级仲裁字段，`schema.sql` 自此为服务端 DDL 唯一出处。
- `v0.1.5-contract`（2026-10-09 补丁，加性向后兼容）：团队 E2EE 总纲定盘（collab §5.3.1）——①`Envelope` 补明文外层 `key_ver` + `member_key_envelopes` 字段与 `MemberKeyEnvelope` 消息（收口「解密前无从选钥」缺口）；②新增 `ADD_MEMBER` 动作（中途加人：现役 key_ver 不变、仅追加新人信封、零 REKEY、可看全量历史）；③新增 `bundle_members` 信封落表（第 10 表）+ `GET /v1/bundles/{id}/key-envelopes` 补拉端点；④密钥保留口径修正：K_bundle 保留至 bundle 生命周期终（金库信封长期留存），废「敲定即销毁」表述。
- `v0.1.6-contract`（2026-10-09 补丁，零字段/零 DDL 行为契约）：①time_anchors 可选 `tz`/`end_tz` 时区锚（cipher 内，缺省本地墙钟零迁移；跨时区行程先折算绝对时刻再运算）；②OPK 空池降级：prekey 恒 200、OPK 空即端侧 4-DH→3-DH（Signal 标准）+ 静默补仓通知；③Wake Push 零知识载荷规范（APNs `content-available`/FCM 纯 data，零明文、本地发声）；④防爆仓硬配额（成员≤16/活跃包≤20/流水≤2000/待审批邀请≤50）；⑤Bundle 终态（CANCELLED/EXPIRED）凭证脱钩转正未归属池（绝不物理删除）；⑥全局错误码字典 + 零明文红线（collab §10.4）。
- **Phase 0 工程产物（本轮新增，非协议变更）**：仓骨架 `go.mod`/`Dockerfile`/`docker-compose.yml`、生成与验收脚本 `scripts/`、proto 补 `go_package` 选项、`schema.sql` 校准（DDL 唯一出处）。
