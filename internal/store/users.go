package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
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
	UserID           string
	IdentityKeyPub   []byte
	SignedPrekeyPub  []byte
	SignedPrekeySig  []byte
	PushToken        string
	EncryptedProfile []byte
	RecoveryVault    []byte
}

// UserStore：users / key_envelopes 的写入与 OPK 消费。
type UserStore struct{ Pool *pgxpool.Pool }

// ErrUserExists：user_id 已占用（或身份公钥重复）。
var ErrUserExists = errors.New("user already exists")

// CreateUserWithPreKeys：单事务建用户 + 首批 OPK。
// 任一环节失败整事务回滚——绝不出现「有用户无密钥」的半截账号（否则对端永远拉不到 KeyBundle）。
func (s UserStore) CreateUserWithPreKeys(ctx context.Context, in CreateUserInput, keys []PreKey) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("开启事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `
		INSERT INTO users (user_id, identity_key_pub, signed_prekey_pub, signed_prekey_sig,
		                   push_token, encrypted_profile, recovery_vault)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (user_id) DO NOTHING`,
		in.UserID, in.IdentityKeyPub, in.SignedPrekeyPub, in.SignedPrekeySig,
		nullText(in.PushToken), in.EncryptedProfile, in.RecoveryVault)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrUserExists
		}
		return fmt.Errorf("写入 users 失败: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserExists
	}

	if err := insertPreKeys(ctx, tx, in.UserID, keys); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("提交事务失败: %w", err)
	}
	return nil
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
