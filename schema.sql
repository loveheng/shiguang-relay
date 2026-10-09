-- ============================================================================
-- shiguang-relay · 数据库契约 (PostgreSQL)  v0.1.6-contract
-- 全量 10 表定盘：4 张底座表（users / friendships / key_envelopes OPK 池 / relay_messages）
--   + 6 张协同表（bundles / bundle_skeletons / bundle_members 密钥信封 / bundle_member_cursors /
--   team_schedule_events / user_key_envelopes）。
-- v0.1.6：零 DDL 变更（行为契约补全：tz 时区锚 / OPK 空池降级 / Wake Push 载荷规范 / 防爆仓配额 / 错误码字典，
--   SSOT=collab §10.4 与 fact §1.2/§5.5）。
-- v0.1.4 ⑤：bundles 与协同 §10.1 列集合流（proposal_type / FSM status / base_revision / participant_uids /
--   expires_at 并入，原存储态独立为 lifecycle 列；skeletons 步骤级仲裁字段定盘进 topology JSONB）。
--   本文件自此为服务端 DDL 唯一出处（防双源漂移）。
--
-- 2026-10-09 服务端架构审查修正内建：
--   - friendships 仅 5 个有意义列 (user_id_a, user_id_b, status, encrypted_intro, created_at)，零 nickname/phone（encrypted_intro 仅 pending 期留存，accept/block 后置 NULL）
--   - users 零 display_name；昵称/备注仅存 encrypted_profile（端侧全密文）
--   - 全库零 entity_key 列（不接收/不存储车次/预约码等业务代号）
--   - team_schedule_events 走全局 seq_id（UNIQUE(bundle_id, seq_id)），服务端绝对定序
--   - relay_messages TTL 即焚（expires_at + status），与持久化事件流解耦
--   - v0.1.2 客户端契约变更（target_step_ref / bundle_id / 块-凭证反转 / 时相公式 / 移动端模板抽取器）全部位于
--     `team_schedule_events.cipher` 解密后的 artifact payload 内，服务端 DDL 零结构变更，本仓维持 v0.1.0 表结构。
--
-- 注意：本文件为 DDL 契约，不含任何 Go 业务代码（Phase 0 停火协议）。
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- 提供 gen_random_uuid()

-- 1) 用户：服务端零明文昵称 ------------------------------------------------
CREATE TABLE users (
  user_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_key_pub   BYTEA NOT NULL,            -- Ed25519 身份公钥
  signed_prekey_pub  BYTEA NOT NULL,            -- X25519 签名预密钥
  signed_prekey_sig  BYTEA NOT NULL,            -- 身份密钥对预密钥的签名
  push_token         TEXT,                      -- FCM/APNs；服务端不解析内容
  encrypted_profile  BYTEA,                     -- 端侧全密文（昵称/备注/头像），服务端不可读
  recovery_vault     BYTEA,                     -- 端侧加密的主密钥恢复金库
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- 注册约束（应用层强制）：必须携带 signed_pop + pow_solution，否则拒收（防女巫/存储轰炸）
  CONSTRAINT users_identity_key_uniq UNIQUE (identity_key_pub)
);

-- 2) 好友关系：仅 5 列（user_id_a / user_id_b / status / encrypted_intro / created_at），零 nickname/phone --
CREATE TABLE friendships (
  user_id_a         UUID NOT NULL REFERENCES users(user_id),
  user_id_b         UUID NOT NULL REFERENCES users(user_id),
  status            TEXT NOT NULL CHECK (status IN ('pending', 'accepted', 'blocked')),
  encrypted_intro   BYTEA,                      -- v0.1.3：A 用 B 公钥 ECIES 加密的自报家门（定长 128B 对齐，防长度侧信道）；仅 pending 期留存，accept/block 后置 NULL
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id_a, user_id_b),
  CONSTRAINT no_self_friend CHECK (user_id_a <> user_id_b)
);
CREATE INDEX idx_friendships_b ON friendships (user_id_b, status);

-- 3) 方案包 bundles：母状态机实体（v0.1.4 ⑤ 与协同 §10.1 列集合流，DDL 唯一出处）--
CREATE TABLE bundles (
  bundle_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  initiator_id     UUID NOT NULL REFERENCES users(user_id),
  proposal_type    TEXT NOT NULL CHECK (proposal_type IN ('DIRECTIVE', 'CONSENSUS')),  -- 团队调度 / 小团体（协同 §4.4）
  status           TEXT NOT NULL DEFAULT 'PROPOSED'
                     CHECK (status IN ('PROPOSED', 'STALLED', 'CONFIRMED', 'CANCELLED', 'EXPIRED')),  -- FSM 状态（协同 §4 转移表）
  lifecycle        TEXT NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active', 'archived')),        -- 存储生命周期（§5.7 归档清事件流依据）
  base_revision    INT NOT NULL DEFAULT 1,       -- 方案整体版本号（§5.4 整包重构校验；事实三动作豁免，v0.1.3）
  max_seq_id       BIGINT NOT NULL DEFAULT 0,    -- 写事件前 SELECT ... FOR UPDATE 行锁取号（§5.1）
  participant_uids UUID[] NOT NULL,               -- 参与全员（寻址 + participating 拉取权限 ACL）
  expires_at       TIMESTAMPTZ NOT NULL,         -- TTL 超时（§3.6 Soft-Lock / §4.4 EXPIRED 扫描依据）
  encrypted_meta   BYTEA,                        -- 端侧加密的 bundle 元信息，服务端不可读
  key_version      INT NOT NULL DEFAULT 1,       -- 当前 K_bundle 版本（REKEY +1，§7.2）
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_bundles_initiator ON bundles (initiator_id, status);
CREATE INDEX idx_bundles_participants ON bundles USING GIN (participant_uids);  -- GET /v1/bundles/participating 数组包含检索

-- 4) 拓扑骨架 bundle_skeletons：Quorum 仲裁（v0.1.4 ⑤ topology JSONB 内部结构定盘，吸收协同 §10.1-2 步骤级字段）--
CREATE TABLE bundle_skeletons (
  skeleton_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  bundle_id     UUID NOT NULL REFERENCES bundles(bundle_id) ON DELETE CASCADE,
  topology      JSONB NOT NULL,                 -- UUID 边，零明文；内部结构定盘（步骤级数组）：
  -- { "steps": [ { "step_id": "...", "required_uids": ["uuid"...], "threshold": 1,
  --     "is_optional": false, "step_status": "PENDING|READY|TIME_CLASH|ROLE_CLASH|PRUNED",
  --     "votes": { "<uid>": "PREFER|OK|NO" } } ] }   -- 门限 M-of-N / Consensus 三值偏好全在此（协同 §4.2/§4.4/§10.1-2）
  quorum        INT NOT NULL DEFAULT 1,          -- bundle 级落槌门限
  version       INT NOT NULL DEFAULT 1,          -- 骨架版本（PATCH/REKEY 推进）
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (bundle_id, skeleton_id)
);

-- 4b) 成员同步游标 bundle_member_cursors（CLIENT_ACK 游标，协同 §10.3-2；v0.1.4 补建）--
CREATE TABLE bundle_member_cursors (
  bundle_id      UUID NOT NULL REFERENCES bundles(bundle_id),
  user_id        UUID NOT NULL REFERENCES users(user_id),
  last_acked_seq BIGINT NOT NULL DEFAULT 0,     -- 服务端按此判定谁漏了事件，只对落后者发 Wake Push
  PRIMARY KEY (bundle_id, user_id)
);

-- 4c) 成员密钥信封 bundle_members（X3DH 包裹的 K_bundle 落表，v0.1.5；服务端纯盲）--
CREATE TABLE bundle_members (
  bundle_id            UUID NOT NULL REFERENCES bundles(bundle_id) ON DELETE CASCADE,
  user_id              UUID NOT NULL REFERENCES users(user_id),
  encrypted_bundle_key BYTEA NOT NULL,          -- X3DH 包裹的 K_bundle 信封（随 PROPOSE/ADD_MEMBER/REKEY 事件明文外层提交）
  key_ver              INT NOT NULL DEFAULT 1,  -- 对应 K_bundle 版本（ADD_MEMBER 不递增；REKEY 全员 +1）
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (bundle_id, user_id, key_ver)     -- 同成员同版本幂等；REKEY 追加新版本行，旧版本保留供离线端回放
);

-- 5) 协同事件流 team_schedule_events：事实/排程统一通道 --------------------
CREATE TABLE team_schedule_events (
  event_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  bundle_id       UUID NOT NULL REFERENCES bundles(bundle_id),
  seq_id          BIGINT NOT NULL,              -- 服务端定序，UNIQUE(bundle_id, seq_id)
  action_type     VARCHAR(32) NOT NULL,         -- Envelope.ActionType 枚举值（含 ATTACH_FACT 等）
  sender_user_id  UUID NOT NULL REFERENCES users(user_id),
  cipher          BYTEA NOT NULL,               -- AEAD(K_bundle, payload)，≤256KB
  topology_ref    UUID REFERENCES bundle_skeletons(skeleton_id),
  client_msg_id   TEXT NOT NULL,                -- 幂等去重键
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (bundle_id, seq_id)
);
CREATE INDEX idx_events_bundle_seq ON team_schedule_events (bundle_id, seq_id);
CREATE INDEX idx_events_client_msg ON team_schedule_events (bundle_id, client_msg_id);

-- 6) 密钥信封 key_envelopes（X3DH OPK 池，即 user_prekeys 语义；GET .../prekey 原子弹出消费、POST /v1/users/me/prekeys 补仓）--
CREATE TABLE key_envelopes (
  user_id    UUID NOT NULL REFERENCES users(user_id),
  key_id     TEXT NOT NULL,
  prekey_pub BYTEA NOT NULL,
  signature  BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, key_id)
);

-- 7) P2P 瞬时信令 relay_messages：TTL 即焚（非 bundle 事件）---------------
CREATE TABLE relay_messages (
  msg_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  recipient_user_id UUID NOT NULL REFERENCES users(user_id),
  sender_user_id    UUID NOT NULL REFERENCES users(user_id),
  kind              TEXT NOT NULL,
  cipher            BYTEA NOT NULL,              -- ≤256KB 网关硬限
  status            TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'delivered', 'acked')),
  expires_at        TIMESTAMPTZ NOT NULL,        -- TTL 即焚；后台清理 cron 删除过期/acked
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_relay_recipient ON relay_messages (recipient_user_id, status, expires_at);

-- 8) 密钥增量金库 user_key_envelopes（换机恢复，Append-Only 防 LWW 擦除，v0.1.3）--
CREATE TABLE user_key_envelopes (
  user_id       UUID NOT NULL REFERENCES users(user_id),
  bundle_id     UUID NOT NULL,
  key_ver       INT NOT NULL,                 -- K_bundle 版本（REKEY 后 +1）
  wrapped_keys  BYTEA NOT NULL,               -- MSK 封送的 K_bundle 信封（服务端不可读）
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, bundle_id, key_ver)   -- 同版本幂等 upsert，新版本追加，杜绝 Last-Write-Wins 覆盖擦除
);
CREATE INDEX idx_user_key_envelopes_user ON user_key_envelopes (user_id, created_at);
