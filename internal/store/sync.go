package store

import (
	"context"
	"fmt"
	"time"
)

const (
	SyncPageSize     = 200 // 单次 sync 默认条数
	SyncPageMax      = 500
	RelayMaxPending  = 200
)

// ParticipatingBundle：发现机制（§10.3-1）返回项——换机冷启动先发现再增量拉取。
type ParticipatingBundle struct {
	BundleID     string
	Status       string
	Lifecycle    string
	MaxSeqID     int64
	LastAckedSeq int64
	ExpiresAt    time.Time
	UpdatedAt    time.Time
	InitiatorID  string
}

// Event：事件流水投影（cipher 原样字节，服务端不解读）。
type Event struct {
	SeqID       int64
	ActionType  string
	SenderID    string
	Cipher      []byte
	TopologyRef string
	CreatedAt   time.Time
}

// ListParticipating：我参与的方案包（含游标，供 Wake Push 判定落后者）。
func (s BundlesStore) ListParticipating(ctx context.Context, userID, lifecycle string) ([]ParticipatingBundle, error) {
	if lifecycle == "" {
		lifecycle = "active"
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT b.bundle_id, b.status, b.lifecycle, b.max_seq_id, b.expires_at, b.updated_at, b.initiator_id,
		       COALESCE(c.last_acked_seq, 0)
		FROM bundles b
		LEFT JOIN bundle_member_cursors c
		       ON c.bundle_id = b.bundle_id AND c.user_id = $1
		WHERE b.participant_uids @> ARRAY[$1]::uuid[] AND b.lifecycle = $2
		ORDER BY b.updated_at DESC`, userID, lifecycle)
	if err != nil {
		return nil, fmt.Errorf("查询参与中方案包失败: %w", err)
	}
	defer rows.Close()

	out := []ParticipatingBundle{}
	for rows.Next() {
		var b ParticipatingBundle
		if err := rows.Scan(&b.BundleID, &b.Status, &b.Lifecycle, &b.MaxSeqID,
			&b.ExpiresAt, &b.UpdatedAt, &b.InitiatorID, &b.LastAckedSeq); err != nil {
			return nil, fmt.Errorf("读取方案包行失败: %w", err)
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// IsParticipant：sync/key-envelopes 的成员校验（§1.7 包内放行）。
func (s BundlesStore) IsParticipant(ctx context.Context, bundleID, userID string) (bool, error) {
	var ok bool
	err := s.Pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM bundles WHERE bundle_id = $1 AND participant_uids @> ARRAY[$2]::uuid[])`,
		bundleID, userID).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("成员校验失败: %w", err)
	}
	return ok, nil
}

// EventsSince：增量事件（跳号补拉：since_seq=0 即全量重放）。
func (s BundlesStore) EventsSince(ctx context.Context, bundleID string, sinceSeq int64, limit int) ([]Event, error) {
	if limit <= 0 {
		limit = SyncPageSize
	}
	if limit > SyncPageMax {
		limit = SyncPageMax
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT seq_id, action_type, sender_user_id, cipher, COALESCE(topology_ref::text, ''), created_at
		FROM team_schedule_events
		WHERE bundle_id = $1 AND seq_id > $2
		ORDER BY seq_id ASC
		LIMIT $3`, bundleID, sinceSeq, limit)
	if err != nil {
		return nil, fmt.Errorf("拉取增量事件失败: %w", err)
	}
	defer rows.Close()

	out := []Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.SeqID, &e.ActionType, &e.SenderID, &e.Cipher, &e.TopologyRef, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("读取事件行失败: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// MemberKeyEnvelopesRow：本成员在指定 bundle 的全版本密钥信封（换机/REKEY 补拉）。
type MemberKeyEnvelopesRow struct {
	KeyVer      int
	WrappedKey  []byte
	CreatedAt   time.Time
}

func (s BundlesStore) MemberKeyEnvelopes(ctx context.Context, bundleID, userID string) ([]MemberKeyEnvelopesRow, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT key_ver, encrypted_bundle_key, created_at
		FROM bundle_members WHERE bundle_id = $1 AND user_id = $2
		ORDER BY key_ver ASC`, bundleID, userID)
	if err != nil {
		return nil, fmt.Errorf("拉取成员信封失败: %w", err)
	}
	defer rows.Close()
	out := []MemberKeyEnvelopesRow{}
	for rows.Next() {
		var r MemberKeyEnvelopesRow
		if err := rows.Scan(&r.KeyVer, &r.WrappedKey, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("读取信封行失败: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// VaultEnvelope：自我备份通道（§5.3）——MSK 封送的 K_bundle 增量信封，Append-Only 防 LWW 覆盖。
type VaultEnvelope struct {
	BundleID    string
	KeyVer      int
	WrappedKeys []byte
	CreatedAt   time.Time
}

// AppendVaultEnvelope：同版本幂等（重复上传不覆盖，绝不 Last-Write-Wins 擦除）。
func (s BundlesStore) AppendVaultEnvelope(ctx context.Context, userID, bundleID string, keyVer int, wrapped []byte) error {
	if _, err := s.Pool.Exec(ctx, `
		INSERT INTO user_key_envelopes (user_id, bundle_id, key_ver, wrapped_keys)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (user_id, bundle_id, key_ver) DO NOTHING`, userID, bundleID, keyVer, wrapped); err != nil {
		return fmt.Errorf("写入金库信封失败: %w", err)
	}
	return nil
}

func (s BundlesStore) ListVaultEnvelopes(ctx context.Context, userID string, sinceVer int) ([]VaultEnvelope, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT bundle_id, key_ver, wrapped_keys, created_at
		FROM user_key_envelopes
		WHERE user_id = $1 AND key_ver > $2
		ORDER BY created_at ASC, key_ver ASC`, userID, sinceVer)
	if err != nil {
		return nil, fmt.Errorf("拉取金库信封失败: %w", err)
	}
	defer rows.Close()
	out := []VaultEnvelope{}
	for rows.Next() {
		var v VaultEnvelope
		if err := rows.Scan(&v.BundleID, &v.KeyVer, &v.WrappedKeys, &v.CreatedAt); err != nil {
			return nil, fmt.Errorf("读取金库行失败: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// RelayMessage：P2P 瞬时信令（TTL 即焚，非 bundle 事件）。
type RelayMessage struct {
	MsgID     string
	SenderID  string
	Kind      string
	Cipher    []byte
	ExpiresAt time.Time
	CreatedAt time.Time
}

// CreateRelayMessage：暂存一条瞬时信令（在线路径由 WSS 直推，离线走 pending 拉取）。
func (s BundlesStore) CreateRelayMessage(ctx context.Context, senderID, recipientID, kind string, cipher []byte, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	var id string
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO relay_messages (recipient_user_id, sender_user_id, kind, cipher, expires_at)
		VALUES ($1,$2,$3,$4, now() + $5::interval)
		RETURNING msg_id::text`, recipientID, senderID, kind, cipher, fmt.Sprintf("%d seconds", int(ttl.Seconds()))).
		Scan(&id)
	if err != nil {
		return "", fmt.Errorf("暂存瞬时信令失败: %w", err)
	}
	return id, nil
}

// PendingRelayMessages：我未消费且未过期的瞬时信令。
func (s BundlesStore) PendingRelayMessages(ctx context.Context, userID string) ([]RelayMessage, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT msg_id::text, sender_user_id, kind, cipher, expires_at, created_at
		FROM relay_messages
		WHERE recipient_user_id = $1 AND status = 'pending' AND expires_at > now()
		ORDER BY created_at ASC
		LIMIT $2`, userID, RelayMaxPending)
	if err != nil {
		return nil, fmt.Errorf("拉取瞬时信令失败: %w", err)
	}
	defer rows.Close()
	out := []RelayMessage{}
	for rows.Next() {
		var m RelayMessage
		if err := rows.Scan(&m.MsgID, &m.SenderID, &m.Kind, &m.Cipher, &m.ExpiresAt, &m.CreatedAt); err != nil {
			return nil, fmt.Errorf("读取信令行失败: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// AckRelayMessages：阅后即焚——先置 acked 再物理 DELETE（只删本人的、未过期的）。
func (s BundlesStore) AckRelayMessages(ctx context.Context, userID string, msgIDs []string) (int, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("开启事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `
		UPDATE relay_messages SET status = 'acked'
		WHERE recipient_user_id = $1 AND status = 'pending' AND msg_id::text = ANY($2)`,
		userID, msgIDs)
	if err != nil {
		return 0, fmt.Errorf("标记已消费失败: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM relay_messages
		WHERE recipient_user_id = $1 AND status = 'acked' AND msg_id::text = ANY($2)`,
		userID, msgIDs); err != nil {
		return 0, fmt.Errorf("清理瞬时信令失败: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("提交事务失败: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
