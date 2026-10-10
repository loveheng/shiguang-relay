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

// 拉黑列表硬配额：单用户 ≤500（blocked 行同样是存储，防女巫灌爆；
// 行方向恒为 (blocker, blocked)，配额只计 blocker 侧）。
const MaxBlockedRelations = 500

var (
	ErrRelationExists   = errors.New("friendship relation already exists")
	ErrInviteNotFound   = errors.New("pending invite not found")
	ErrRelationNotFound = errors.New("friendship relation not found")
)

// Friendship：一条好友关系（返回给调用方时 user_id 恒为「对方」）。
type Friendship struct {
	UserID         string    `json:"user_id"`
	Username       string    `json:"username"` // 对方用户名（明文标识符，客户端解密 encrypted_profile 前的展示锚点）
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
	EncryptedIntro []byte    `json:"-"` // 仅被邀方在 pending 期可见（端侧私钥解密）
	AmInvitee      bool      `json:"-"` // 调用方是否为 user_id_b（被邀方）——决定 intro 是否回包
}

// FriendsStore：friendships 的写入与查询。
type FriendsStore struct{ Pool *pgxpool.Pool }

// CreatePending：写 pending（A=扫码发起人，B=Ticket 签发人）。
// 已存在（含 accepted/blocked）→ ErrRelationExists，由接口层转 409。
// blocked 双向静默：任一方向存在 blocked 行（尤其反向——B 拉黑 A 后 A 换方向重发）
// 均返回同一 ErrRelationExists，不告知被拉黑事实（防骚扰语义）。
func (s FriendsStore) CreatePending(ctx context.Context, a, b string, encryptedIntro []byte) error {
	var n int
	if err := s.Pool.QueryRow(ctx, `
		SELECT count(*) FROM friendships
		WHERE status = 'blocked'
		  AND ((user_id_a = $1 AND user_id_b = $2) OR (user_id_a = $2 AND user_id_b = $1))`, a, b).
		Scan(&n); err != nil {
		return fmt.Errorf("拉黑检查失败: %w", err)
	}
	if n > 0 {
		return ErrRelationExists
	}
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

// Remove：解除关系（删除好友 / 撤回申请 / 解除拉黑）——双向命中，行级删除。
// 语义 = 「斩断并遗忘」：双方回到陌生状态，此后可重新申请。
// 返回是否确有关系被删（无 → ErrRelationNotFound，接口层转 404）。
func (s FriendsStore) Remove(ctx context.Context, caller, peer string) error {
	tag, err := s.Pool.Exec(ctx, `
		DELETE FROM friendships
		WHERE (user_id_a = $1 AND user_id_b = $2) OR (user_id_a = $2 AND user_id_b = $1)`,
		caller, peer)
	if err != nil {
		return fmt.Errorf("解除好友关系失败: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrRelationNotFound
	}
	return nil
}

// Block：主动拉黑（无需既有关系）。
// 语义：blocked 方向恒为 (a=blocker, b=blocked)——与 pending 的「a=动作发起方」一致；
// 单事务先删反向行再正向 upsert，保证任一时刻该用户对至多一行、且方向唯一：
//   - 反向行（blocked 曾发起的关系）无论状态一律删除；
//   - 正向行 pending/accepted → 转 blocked（encrypted_intro 清空，与 Respond 同口径）。
// 被拉黑方此后任何方向的申请都会被 CreatePending 双向检查静默拒绝。
func (s FriendsStore) Block(ctx context.Context, blocker, blocked string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("开启事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		DELETE FROM friendships WHERE user_id_a = $1 AND user_id_b = $2`, blocked, blocker); err != nil {
		return fmt.Errorf("清理反向关系失败: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO friendships (user_id_a, user_id_b, status, encrypted_intro)
		VALUES ($1,$2,'blocked',NULL)
		ON CONFLICT (user_id_a, user_id_b)
		DO UPDATE SET status = 'blocked', encrypted_intro = NULL`, blocker, blocked); err != nil {
		return fmt.Errorf("写入拉黑关系失败: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("提交拉黑事务失败: %w", err)
	}
	return nil
}

// CountBlockedBy：某人拉黑列表规模（存储配额判定用，只计 blocker 侧）。
func (s FriendsStore) CountBlockedBy(ctx context.Context, userID string) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `
		SELECT count(*) FROM friendships
		WHERE status = 'blocked' AND user_id_a = $1`, userID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("统计拉黑列表失败: %w", err)
	}
	return n, nil
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

// List：我的好友关系（双向命中），对方视角返回（含对方 username）。
func (s FriendsStore) List(ctx context.Context, userID string) ([]Friendship, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT p.peer, u.username, p.status, p.created_at, p.encrypted_intro, p.am_invitee
		FROM (
			SELECT CASE WHEN user_id_a = $1 THEN user_id_b ELSE user_id_a END AS peer,
			       status, created_at, encrypted_intro, (user_id_b = $1) AS am_invitee
			FROM friendships
			WHERE user_id_a = $1 OR user_id_b = $1
		) p
		JOIN users u ON u.user_id = p.peer
		ORDER BY p.created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("查询好友列表失败: %w", err)
	}
	defer rows.Close()

	out := []Friendship{}
	for rows.Next() {
		var f Friendship
		if err := rows.Scan(&f.UserID, &f.Username, &f.Status, &f.CreatedAt, &f.EncryptedIntro, &f.AmInvitee); err != nil {
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
