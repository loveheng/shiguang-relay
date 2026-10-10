package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"shiguang-relay/internal/auth"
)

// 注册瘦身策略（fact §7.1-2 / 协同 §1.5）：首批 OPK 10~20 个（单账号 DB <1KB，防 Sybil 撑爆磁盘）；
// 补仓每批上限 50（心跳/低存量触发）。
const (
	MinInitialPreKeys = 10
	MaxInitialPreKeys = 20
	MaxRefillPreKeys  = 50
	LowPreKeyWatermark = 5 // 低于此值随心跳提示补仓（OPK_EMPTY_WARNING 邻近阈值）
)

// PreKey：一次性预密钥（X3DH OPK）。
type PreKey struct {
	KeyID     string `json:"key_id"`
	Pub       []byte `json:"pub"`
	Signature []byte `json:"signature"`
}

// IdentityBundle：X3DH KeyBundle（身份公钥 + 签名预密钥 + 弹出的 1 个 OPK）。
type IdentityBundle struct {
	IdentityKeyPub  []byte
	SignedPrekeyPub []byte
	SignedPrekeySig []byte
	OneTimePreKeys  []PreKey
	RemainingOPK    int
}

type CreateUserInput struct {
	Username         string // 人类可读唯一标识（小写字母/数字/下划线），账号体系，非业务数据
	PasswordHash     string // 派生哈希（auth.HashPassword），服务端零明文密码
	IdentityKeyPub   []byte
	SignedPrekeyPub  []byte
	SignedPrekeySig  []byte
	PushToken        string
	EncryptedProfile []byte
	RecoveryVault    []byte
}

// UserStore：users / key_envelopes 的写入与 OPK 消费。
type UserStore struct{ Pool *pgxpool.Pool }

// ErrUserExists：身份公钥重复（同密钥重复注册）。
var ErrUserExists = errors.New("user already exists")

// ErrUsernameExists：username 唯一约束冲突。
var ErrUsernameExists = errors.New("username already exists")

// ErrUserNotFound：用户不存在（按 user_id 定位失败）。
var ErrUserNotFound = errors.New("user not found")

// CreateUserWithPreKeys：单事务建用户（服务端生成 user_id）+ 首批 OPK。
// 任一环节失败整事务回滚——绝不出现「有用户无密钥」的半截账号（否则对端永远拉不到 KeyBundle）。
// user_id 由库默认 gen_random_uuid() 生成并通过 RETURNING 取回。
func (s UserStore) CreateUserWithPreKeys(ctx context.Context, in CreateUserInput, keys []PreKey) (string, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("开启事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var userID string
	err = tx.QueryRow(ctx, `
		INSERT INTO users (username, password_hash, identity_key_pub, signed_prekey_pub, signed_prekey_sig,
		                   push_token, encrypted_profile, recovery_vault)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING user_id`,
		in.Username, in.PasswordHash, in.IdentityKeyPub, in.SignedPrekeyPub, in.SignedPrekeySig,
		nullText(in.PushToken), in.EncryptedProfile, in.RecoveryVault).Scan(&userID)
	if err != nil {
		if isUniqueViolation(err) {
			// 不依赖约束名（唯一索引/约束命名随部署而异）：回查 username 占用与否区分两类冲突
			var exists bool
			if qerr := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)`, in.Username).Scan(&exists); qerr == nil && exists {
				return "", ErrUsernameExists
			}
			return "", ErrUserExists
		}
		return "", fmt.Errorf("写入 users 失败: %w", err)
	}

	if err := insertPreKeys(ctx, tx, userID, keys); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("提交事务失败: %w", err)
	}
	return userID, nil
}

// VerifyPassword：按 username 取 user_id + 哈希并校验（恒定时间）。
// 用户不存在返回 ok=false（与密码错误同一口径，避免账号枚举侧信道）。
func (s UserStore) VerifyPassword(ctx context.Context, username, password string) (string, bool, error) {
	var userID, hash string
	err := s.Pool.QueryRow(ctx, `SELECT user_id, password_hash FROM users WHERE username = $1`, username).
		Scan(&userID, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("查询密码失败: %w", err)
	}
	return userID, auth.VerifyPassword(hash, password), nil
}

// CheckPasswordByUserID：按 user_id 校验旧密码（改密用）。
func (s UserStore) CheckPasswordByUserID(ctx context.Context, userID, password string) (bool, error) {
	var hash string
	err := s.Pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE user_id = $1`, userID).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("查询密码失败: %w", err)
	}
	return auth.VerifyPassword(hash, password), nil
}

// UpdatePassword：更新密码哈希（Plan A：仅换哈希，不动 E2EE 密钥）。
func (s UserStore) UpdatePassword(ctx context.Context, userID, newHash string) error {
	tag, err := s.Pool.Exec(ctx,
		`UPDATE users SET password_hash = $1, updated_at = now() WHERE user_id = $2`, newHash, userID)
	if err != nil {
		return fmt.Errorf("更新密码失败: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

// PublicIdentity：用户名搜索返回的公钥身份（不含私钥，服务端纯盲）。
type PublicIdentity struct {
	UserID          string
	Username        string
	IdentityKeyPub  []byte
	SignedPrekeyPub []byte
	SignedPrekeySig []byte
}

// PublicIdentityByUsername：按 username 取用户公钥身份（加好友「搜索」路径）。
// 不弹出 OPK（X3DH 用 OPK 由调用方走 GET /v1/users/{id}/prekey 单独拉取）。
func (s UserStore) PublicIdentityByUsername(ctx context.Context, username string) (PublicIdentity, bool, error) {
	var p PublicIdentity
	err := s.Pool.QueryRow(ctx, `
		SELECT user_id, username, identity_key_pub, signed_prekey_pub, signed_prekey_sig
		FROM users WHERE username = $1`, username).
		Scan(&p.UserID, &p.Username, &p.IdentityKeyPub, &p.SignedPrekeyPub, &p.SignedPrekeySig)
	if errors.Is(err, pgx.ErrNoRows) {
		return PublicIdentity{}, false, nil
	}
	if err != nil {
		return PublicIdentity{}, false, fmt.Errorf("查询公钥身份失败: %w", err)
	}
	return p, true, nil
}

// InsertPreKeys：OPK 补仓（同 key_id 幂等忽略）。
func (s UserStore) InsertPreKeys(ctx context.Context, userID string, keys []PreKey) (int, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("开启事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := insertPreKeys(ctx, tx, userID, keys); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("提交事务失败: %w", err)
	}
	return len(keys), nil
}

func insertPreKeys(ctx context.Context, tx pgx.Tx, userID string, keys []PreKey) error {
	for _, k := range keys {
		if _, err := tx.Exec(ctx, `
			INSERT INTO key_envelopes (user_id, key_id, prekey_pub, signature)
			VALUES ($1,$2,$3,$4) ON CONFLICT (user_id, key_id) DO NOTHING`,
			userID, k.KeyID, k.Pub, k.Signature); err != nil {
			if isUniqueViolation(err) {
				return ErrUserExists // identity_key 唯一约束等冲突
			}
			return fmt.Errorf("写入 OPK 失败: %w", err)
		}
	}
	return nil
}

// PopOneTimePreKey：原子弹出 1 个 OPK（FOR UPDATE SKIP LOCKED + DELETE RETURNING）。
// 并发拉取不会拿到同一条：SKIP LOCKED 让第二个事务直接跳过被锁行。
// 返回 remaining 供服务端决定是否在响应里带 OPK_EMPTY_WARNING 提示。
func (s UserStore) PopOneTimePreKey(ctx context.Context, userID string) (*PreKey, int, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("开启事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var pk PreKey
	err = tx.QueryRow(ctx, `
		WITH popped AS (
			SELECT user_id, key_id FROM key_envelopes
			WHERE user_id = $1
			ORDER BY created_at, key_id
			LIMIT 1
			FOR UPDATE SKIP LOCKED
		)
		DELETE FROM key_envelopes k
		USING popped p
		WHERE k.user_id = p.user_id AND k.key_id = p.key_id
		RETURNING k.key_id, k.prekey_pub, k.signature`, userID).
		Scan(&pk.KeyID, &pk.Pub, &pk.Signature)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// 空池：v0.1.6 口径——返回 200 + 空列表，端侧降级 3-DH（Signal 标准）
			rem, cerr := countPreKeys(ctx, tx, userID)
			if cerr != nil {
				return nil, 0, cerr
			}
			_ = tx.Commit(ctx)
			return nil, rem, nil
		}
		return nil, 0, fmt.Errorf("弹出 OPK 失败: %w", err)
	}

	rem, err := countPreKeys(ctx, tx, userID)
	if err != nil {
		return nil, 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, 0, fmt.Errorf("提交事务失败: %w", err)
	}
	return &pk, rem, nil
}

// IdentityBundle：取身份公钥 + 签名预密钥 + 原子弹出 1 个 OPK（供 X3DH 包裹 K_bundle）。
// 用户不存在返回 found=false。
func (s UserStore) IdentityBundle(ctx context.Context, userID string) (IdentityBundle, bool, error) {
	var b IdentityBundle
	err := s.Pool.QueryRow(ctx, `
		SELECT identity_key_pub, signed_prekey_pub, signed_prekey_sig
		FROM users WHERE user_id = $1`, userID).
		Scan(&b.IdentityKeyPub, &b.SignedPrekeyPub, &b.SignedPrekeySig)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return IdentityBundle{}, false, nil
		}
		return IdentityBundle{}, false, fmt.Errorf("查询身份包失败: %w", err)
	}
	pk, rem, err := s.PopOneTimePreKey(ctx, userID)
	if err != nil {
		return IdentityBundle{}, false, err
	}
	if pk != nil {
		b.OneTimePreKeys = []PreKey{*pk}
	}
	b.RemainingOPK = rem
	return b, true, nil
}

// CountPreKeys：存量计数（补仓决策 / 低水位提示）。
func (s UserStore) CountPreKeys(ctx context.Context, userID string) (int, error) {
	return countPreKeys(ctx, s.Pool, userID)
}

func countPreKeys(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, userID string) (int, error) {
	var n int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM key_envelopes WHERE user_id = $1`, userID).Scan(&n); err != nil {
		return 0, fmt.Errorf("统计 OPK 失败: %w", err)
	}
	return n, nil
}

func nullText(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

// TouchUpdatedAt：用户资料类更新时维护 updated_at（注册之外的资料更新路径使用）。
func (s UserStore) TouchUpdatedAt(ctx context.Context, userID string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE users SET updated_at = now() WHERE user_id = $1`, userID)
	return err
}

// SelfIdentity：自账户读回（GET /v1/users/me）。
// 换机恢复链路的关键一环：recovery_vault 此前只写不读，恢复链路断裂；
// 本方法让新设备登录后能取回端侧加密金库与密文资料（服务端纯盲，不解密）。
type SelfIdentity struct {
	UserID           string    `json:"user_id"`
	Username         string    `json:"username"`
	EncryptedProfile []byte    `json:"encrypted_profile,omitempty"` // 端侧密文（昵称/备注/头像），NULL→空
	RecoveryVault    []byte    `json:"recovery_vault,omitempty"`    // 端侧加密主密钥金库，NULL→空
	CreatedAt        time.Time `json:"-"`
}

func (s UserStore) SelfIdentity(ctx context.Context, userID string) (SelfIdentity, bool, error) {
	var self SelfIdentity
	err := s.Pool.QueryRow(ctx, `
		SELECT user_id, username, encrypted_profile, recovery_vault, created_at
		FROM users WHERE user_id = $1`, userID).
		Scan(&self.UserID, &self.Username, &self.EncryptedProfile, &self.RecoveryVault, &self.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SelfIdentity{}, false, nil
		}
		return SelfIdentity{}, false, fmt.Errorf("查询自账户失败: %w", err)
	}
	return self, true, nil
}

// UpdateEncryptedProfile：替换端侧密文资料（服务端纯盲，PATCH /v1/users/me）。
func (s UserStore) UpdateEncryptedProfile(ctx context.Context, userID string, profile []byte) error {
	tag, err := s.Pool.Exec(ctx, `
		UPDATE users SET encrypted_profile = $2, updated_at = now() WHERE user_id = $1`,
		userID, profile)
	if err != nil {
		return fmt.Errorf("更新密文资料失败: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

// UpdateRecoveryVault：替换端侧加密金库（服务端纯盲，PATCH /v1/users/me）。
// 场景：客户端轮换金库包裹钥 / 修复包裹口径（注意：包裹钥必须独立于登录密码，
// 改密不解密金库，也就不需要因改密而重包裹——见 docs/api/user-accounts.md §5）。
func (s UserStore) UpdateRecoveryVault(ctx context.Context, userID string, vault []byte) error {
	tag, err := s.Pool.Exec(ctx, `
		UPDATE users SET recovery_vault = $2, updated_at = now() WHERE user_id = $1`,
		userID, vault)
	if err != nil {
		return fmt.Errorf("更新恢复金库失败: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

// UpdatePushToken：更新推送令牌（FCM/APNs 换发后调用）；空串视为清空（NULL）。
func (s UserStore) UpdatePushToken(ctx context.Context, userID, token string) error {
	tag, err := s.Pool.Exec(ctx, `
		UPDATE users SET push_token = $2, updated_at = now() WHERE user_id = $1`,
		userID, nullText(token))
	if err != nil {
		return fmt.Errorf("更新推送令牌失败: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}
