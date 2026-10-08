-- ============================================================================
-- 拾光盲中继 PG 初始化 DDL（Phase 0 基线，2026-10-09 用户拍板）
-- 设计 SSOT: docs/design/collab-schedule-draft.md §1.1 / §5.1 / §10.1
-- 验收线: psql -f schema.sql 本地建库成功；UNIQUE(bundle_id, seq_id) 在位
-- 注意: 本文件不含任何 Go 业务代码，仅契约（停火协议）。
-- 灾备: 配合 Litestream / 定时 pg_dump sidecar 每小时异地备份（隐患2 防线）。
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. 用户（纯标识符 + 公钥托管 + 加密资料，§1.1）
CREATE TABLE users (
    account_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_key_pub  BYTEA NOT NULL,              -- Ed25519 验签
    signed_prekey_pub BYTEA NOT NULL,              -- SPK X25519
    push_token        TEXT,                        -- FCM/APNs 唤醒
    encrypted_profile BYTEA,                       -- 端侧加密昵称/头像（服务端盲）
    recovery_vault    BYTEA,                       -- 密钥恢复金库（§5.3）
    created_at        TIMESTAMPTZ DEFAULT NOW(),
    updated_at        TIMESTAMPTZ DEFAULT NOW()
);

-- 2. One-Time PreKey 池（≤100 OPK/人，§1.5 防 OPK 枯竭风暴）
CREATE TABLE user_prekeys (
    account_id UUID NOT NULL REFERENCES users(account_id) ON DELETE CASCADE,
    key_id     INT  NOT NULL,
    public_key BYTEA NOT NULL,
    used       BOOLEAN DEFAULT FALSE,
    PRIMARY KEY (account_id, key_id)
);

-- 3. 好友关系（⚠️ Q1 匿名隔离底线：严格只 4 列，绝无 nickname/phone 明文）
--    好友备注名/头像走端侧加密，存客户端本地或 users.encrypted_profile，服务端零明文。
--    存储约定: (user_id_a, user_id_b) 按 UUID 字典序规范化（min,max），避免双向重复行。
CREATE TABLE friendships (
    user_id_a  UUID NOT NULL REFERENCES users(account_id) ON DELETE CASCADE,
    user_id_b  UUID NOT NULL REFERENCES users(account_id) ON DELETE CASCADE,
    status     VARCHAR(16) NOT NULL DEFAULT 'pending', -- pending/accepted/blocked
    created_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (user_id_a, user_id_b),
    CONSTRAINT no_self_friend CHECK (user_id_a <> user_id_b)
);

-- 4. 存储配置指针（§5，BYOS）
CREATE TABLE user_storage_configs (
    account_id         UUID PRIMARY KEY REFERENCES users(account_id) ON DELETE CASCADE,
    storage_type       VARCHAR(32) NOT NULL,        -- webdav/s3/r2
    endpoint_url       TEXT,
    encrypted_auth_data BYTEA,
    config_version     INT NOT NULL DEFAULT 1
);

-- 5. 方案包根表（母状态机实体，§10.1）
CREATE TABLE bundles (
    bundle_id        VARCHAR(64) PRIMARY KEY,
    initiator_id     UUID NOT NULL REFERENCES users(account_id),
    proposal_type    VARCHAR(32) NOT NULL,          -- DIRECTIVE / CONSENSUS
    status           VARCHAR(32) NOT NULL DEFAULT 'PROPOSED',
                                                      -- PROPOSED/STALLED/CONFIRMED/CANCELLED/EXPIRED
    base_revision    INT NOT NULL DEFAULT 1,        -- 方案整体版本号（§5.4）
    max_seq_id       BIGINT NOT NULL DEFAULT 0,     -- 行锁原子自增（§5.1）
    participant_uids UUID[] NOT NULL,               -- 参与全员（寻址 + 拉取 ACL）
    expires_at       TIMESTAMPTZ NOT NULL,          -- TTL（§3.6 Soft-Lock / §4.4 EXPIRED）
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    updated_at       TIMESTAMPTZ DEFAULT NOW()
);

-- 6. 协作拓扑骨架表（M-of-N 门限 + Consensus 三值仲裁，§10.1）
CREATE TABLE bundle_skeletons (
    bundle_id    VARCHAR(64) NOT NULL REFERENCES bundles(bundle_id) ON DELETE CASCADE,
    step_id      VARCHAR(64) NOT NULL,
    required_uids UUID[] NOT NULL,
    threshold    INT NOT NULL DEFAULT 1,
    is_optional  BOOLEAN DEFAULT FALSE,
    step_status  VARCHAR(32) DEFAULT 'PENDING',
    votes        JSONB DEFAULT '{}'::jsonb,
    PRIMARY KEY (bundle_id, step_id)
);

-- 7. 成员同步游标表（离线精准 Push、避免在线重复推送，§10.1）
CREATE TABLE bundle_member_cursors (
    bundle_id     VARCHAR(64) NOT NULL,
    user_id       UUID NOT NULL,
    last_acked_seq BIGINT DEFAULT 0,
    PRIMARY KEY (bundle_id, user_id)
);

-- 8. 单一事实源事件流（状态 + 密文原子绑定，§5.1；绝不阅后即焚）
CREATE TABLE team_schedule_events (
    id                BIGSERIAL PRIMARY KEY,
    bundle_id         VARCHAR(64) NOT NULL,
    seq_id            BIGINT NOT NULL,              -- bundle 内严格单调
    sender_id         UUID NOT NULL,
    action_type       VARCHAR(32) NOT NULL,         -- 服务端可见枚举
    step_id           VARCHAR(64),
    encrypted_payload TEXT NOT NULL,                -- 端到端密文（Base64）
    iv                VARCHAR(32) NOT NULL,         -- 12B
    auth_tag          VARCHAR(32) NOT NULL,         -- 16B GCM
    key_ver           INT NOT NULL DEFAULT 1,
    created_at        TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (bundle_id, seq_id)
);

-- 9. 用户密钥信封增量表（Append-Only，防 LWW 擦除，§5.3）
CREATE TABLE user_key_envelopes (
    account_id   UUID NOT NULL REFERENCES users(account_id) ON DELETE CASCADE,
    bundle_id    VARCHAR(64) NOT NULL,
    key_ver      INT NOT NULL,
    wrapped_keys BYTEA NOT NULL,                    -- MSK 封送的 K_bundle 信封
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (account_id, bundle_id, key_ver)
);

-- 10. 点对点瞬时信令信箱（阅后即焚，§2.1；与事件流生命周期互斥）
CREATE TABLE relay_messages (
    message_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    recipient_id   UUID NOT NULL,
    sender_id      UUID NOT NULL,
    encrypted_payload TEXT NOT NULL,
    status         VARCHAR(16) DEFAULT 'QUEUED',    -- QUEUED/DELIVERED/FAILED
    retry_count    INT DEFAULT 0,
    next_retry_at  TIMESTAMPTZ,
    expires_at     TIMESTAMPTZ NOT NULL,             -- 动态 TTL（§2.2）
    created_at     TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_relay_messages_recipient ON relay_messages(recipient_id, status);

-- ===== 索引 =====
CREATE INDEX idx_friendships_a ON friendships(user_id_a);
CREATE INDEX idx_friendships_b ON friendships(user_id_b);
CREATE INDEX idx_bundles_participants ON bundles USING GIN(participant_uids);
CREATE INDEX idx_events_bundle_seq ON team_schedule_events(bundle_id, seq_id);

-- ===== seq_id 取号（行级排他锁原子自增，§5.1 并发踩坑防线）=====
-- 禁止 SELECT MAX + 1：PG READ COMMITTED 下同毫秒提交会算重。定稿单条 SQL 拿号：
--   UPDATE bundles SET max_seq_id = max_seq_id + 1, updated_at = NOW()
--   WHERE bundle_id = $1 RETURNING max_seq_id;
-- 拿返回值直接 INSERT team_schedule_events，消除应用层算号重试。

-- ===== FORCE_FINALIZE 并发门禁（§4.4 First-Commit-Wins）=====
--   UPDATE bundles SET status = 'CONFIRMED'
--   WHERE bundle_id = $1 AND status = 'PROPOSING';
--   RowsAffected == 0 → 返回 409 ALREADY_FINALIZED。
