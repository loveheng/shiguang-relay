package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 待审批邀请硬配额（§10.4）：单用户 ≤50，防扫码灌爆 Pending 列表。
const MaxPendingInvites = 50

var (
	ErrRelationExists = errors.New("friendship relation already exists")
	ErrInviteNotFound = errors.New("pending invite not found")
)

// Friendship：一条好友关系（返回给调用方时 user_id 恒为「对方」）。
type Friendship struct {
	UserID         string    `json:"user_id"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
	EncryptedIntro []byte    `json:"-"` // 仅被邀方在 pending 期可见（端侧私钥解密）
	AmInvitee      bool      `json:"-"` // 调用方是否为 user_id_b（被邀方）——决定 intro 是否回包
}

// FriendsStore：friendships 的写入与查询。
type FriendsStore struct{ Pool *pgxpool.Pool }

// CreatePending：写 pending（A=扫码发起人，B=Ticket 签发人）。
// 已存在（含 accepted/blocked）→ ErrRelationExists，由接口层转 409。
func (s FriendsStore) CreatePending(ctx context.Context, a, b string, encryptedIntro []byte) error {
	tag, err := s.Pool.Exec(ctx, `
		INSERT INTO friendships (user_id_a, user_id_b, status, encrypted_intro)
		VALUES ($1,$2,'pending',$3)
		ON CONFLICT (user_id_a, user_id_b) DO NOTHING`, a, b, encryptedIntro)
	if err != nil {
		return fmt.Errorf("写入好友关系失败: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrRelationExists
	}
	return nil
}

// Respond：被邀方 B 处置邀请（accept=true → accepted；false → blocked）。
// 只有 pending 且调用方确为 user_id_b 才生效——防 A 自己批准自己的申请。
func (s FriendsStore) Respond(ctx context.Context, invitee, a, b string, accept bool) error {
	status := "blocked"
	if accept {
		status = "accepted"
	}
	tag, err := s.Pool.Exec(ctx, `
		UPDATE friendships
		SET status = $4, encrypted_intro = NULL
		WHERE user_id_a = $1 AND user_id_b = $2 AND status = 'pending' AND user_id_b = $3`,
		a, b, invitee, status)
	if err != nil {
		return fmt.Errorf("处置邀请失败: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrInviteNotFound
	}
	return nil
}

// List：我的好友关系（双向命中），对方视角返回。
func (s FriendsStore) List(ctx context.Context, userID string) ([]Friendship, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT CASE WHEN user_id_a = $1 THEN user_id_b ELSE user_id_a END AS peer,
		       status, created_at, encrypted_intro, (user_id_b = $1) AS am_invitee
		FROM friendships
		WHERE user_id_a = $1 OR user_id_b = $1
		ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("查询好友列表失败: %w", err)
	}
	defer rows.Close()

	out := []Friendship{}
	for rows.Next() {
		var f Friendship
		if err := rows.Scan(&f.UserID, &f.Status, &f.CreatedAt, &f.EncryptedIntro, &f.AmInvitee); err != nil {
			return nil, fmt.Errorf("读取好友行失败: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// IsAcceptedFriend：双向 accepted 判定（瞬时直投信令 / 建包准入严管共用）。
func (s FriendsStore) IsAcceptedFriend(ctx context.Context, a, b string) (bool, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `
		SELECT count(*) FROM friendships
		WHERE status = 'accepted'
		  AND ((user_id_a = $1 AND user_id_b = $2) OR (user_id_a = $2 AND user_id_b = $1))`, a, b).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("好友校验失败: %w", err)
	}
	return n > 0, nil
}

// CountPendingInvolving：与某人相关的待审批邀请数（配额判定用）。
func (s FriendsStore) CountPendingInvolving(ctx context.Context, userID string) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `
		SELECT count(*) FROM friendships
		WHERE status = 'pending' AND (user_id_a = $1 OR user_id_b = $1)`, userID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("统计待审批邀请失败: %w", err)
	}
	return n, nil
}
