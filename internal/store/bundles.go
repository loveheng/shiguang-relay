package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 防爆仓硬配额（§10.4）：阈值钉在代码里，服务端网关与 FSM 仲裁层单一出处。
const (
	MaxBundleMembers   = 16 // 单 Bundle 成员数（可配放宽至 32）
	MaxActiveBundles   = 20 // 单用户活跃方案包
	MaxBundleEvents    = 2000
	DefaultBundleTTL   = 14 * 24 * time.Hour
)

// 事实三动作：显式绕过 base_revision 乐观锁（v0.1.3），仅取 seq，防假性冲突惊群。
var factActions = map[string]bool{
	"ATTACH_FACT": true,
	"UPDATE_FACT": true,
	"DETACH_FACT": true,
}

// IsFactAction：事实挂载类动作不参与因果冲突判定。
func IsFactAction(action string) bool { return factActions[action] }

var (
	ErrBundleNotFound   = errors.New("bundle not found")
	ErrNotParticipant   = errors.New("sender is not a participant of bundle")
	ErrNotInitiator     = errors.New("only the initiator may perform this action")
	ErrBundleConfirmed  = errors.New("bundle already confirmed")
	ErrStaleRevision    = errors.New("stale base revision")
	ErrEventQuota       = errors.New("bundle event quota exceeded")
	ErrTooManyMembers   = errors.New("too many bundle members")
	ErrTooManyBundles   = errors.New("too many active bundles")
)

type MemberKeyEnvelope struct {
	RecipientUserID string `json:"recipient_user_id"`
	WrappedKey      []byte `json:"wrapped_key"`
	KeyVer          int    `json:"key_ver"`
}

type ProposeInput struct {
	InitiatorID   string
	ProposalType  string
	ParticipantIDs []string
	ExpiresAt     time.Time
	EncryptedMeta []byte
	Topology      json.RawMessage
	Quorum        int
	Envelopes     []MemberKeyEnvelope
	Action        string
	Cipher        []byte
	ClientMsgID   string
}

type ProposeResult struct {
	BundleID    string
	SkeletonID  string
	SeqID       int64
	Status      string
	ExpiresAt   time.Time
}

// BundlesStore：方案包的建包与事件追加（全部单事务）。
type BundlesStore struct{ Pool *pgxpool.Pool }

// Propose：建包（bundles + skeleton + 成员信封 + seq:1 事件）原子完成。
// 顺序刻意如此：先插入 bundle 拿到行锁，后续取号、落骨架、落信封都在同一事务内——
// 杜绝「有包无骨架 / 有事件无信封」的半截状态。
func (s BundlesStore) Propose(ctx context.Context, in ProposeInput) (ProposeResult, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ProposeResult{}, fmt.Errorf("开启事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 活跃包配额（发起人维度）
	var active int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM bundles WHERE initiator_id = $1 AND lifecycle = 'active'`,
		in.InitiatorID).Scan(&active); err != nil {
		return ProposeResult{}, fmt.Errorf("统计活跃包失败: %w", err)
	}
	if active >= MaxActiveBundles {
		return ProposeResult{}, ErrTooManyBundles
	}
	if len(in.ParticipantIDs) > MaxBundleMembers {
		return ProposeResult{}, ErrTooManyMembers
	}

	var bundleID, skeletonID string
	var expiresAt time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO bundles (initiator_id, proposal_type, participant_uids, expires_at, encrypted_meta)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING bundle_id, expires_at`,
		in.InitiatorID, in.ProposalType, in.ParticipantIDs, in.ExpiresAt, in.EncryptedMeta).
		Scan(&bundleID, &expiresAt)
	if err != nil {
		return ProposeResult{}, fmt.Errorf("创建 bundle 失败: %w", err)
	}

	if len(in.Topology) == 0 {
		in.Topology = json.RawMessage(`{"steps":[]}`)
	}
	quorum := in.Quorum
	if quorum <= 0 {
		quorum = 1
	}
	if err := tx.QueryRow(ctx, `
		INSERT INTO bundle_skeletons (bundle_id, topology, quorum)
		VALUES ($1,$2,$3) RETURNING skeleton_id`, bundleID, in.Topology, quorum).
		Scan(&skeletonID); err != nil {
		return ProposeResult{}, fmt.Errorf("创建骨架失败: %w", err)
	}

	for _, e := range in.Envelopes {
		if _, err := tx.Exec(ctx, `
			INSERT INTO bundle_members (bundle_id, user_id, encrypted_bundle_key, key_ver)
			VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
			bundleID, e.RecipientUserID, e.WrappedKey, e.KeyVer); err != nil {
			return ProposeResult{}, fmt.Errorf("落成员信封失败: %w", err)
		}
	}

	seq, err := takeSeq(ctx, tx, bundleID)
	if err != nil {
		return ProposeResult{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO team_schedule_events (bundle_id, seq_id, action_type, sender_user_id, cipher, topology_ref, client_msg_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		bundleID, seq, in.Action, in.InitiatorID, in.Cipher, skeletonID, in.ClientMsgID); err != nil {
		return ProposeResult{}, fmt.Errorf("写入事件失败: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return ProposeResult{}, fmt.Errorf("提交事务失败: %w", err)
	}
	return ProposeResult{BundleID: bundleID, SkeletonID: skeletonID, SeqID: seq, Status: "PROPOSED", ExpiresAt: expiresAt}, nil
}

type AppendInput struct {
	BundleID     string
	SenderID     string
	Action       string
	Cipher       []byte
	ClientMsgID  string
	Topology     json.RawMessage // 结构变更类动作携带的新骨架（PATCH/PRUNE/REASSIGN/ADD_MEMBER）
	Envelopes    []MemberKeyEnvelope
	ExpectRev    *int   // 发起人整体重构时的因果校验（事实三动作豁免）
	SetStatus    string // 终态动作：CONFIRMED / CANCELLED
	BumpKeyVer   bool   // REKEY
	AddMembers   []string // ADD_MEMBER：并入 participant_uids（含配额校验）
}

type AppendResult struct {
	SeqID     int64
	Status    string
	KeyVer    int
	Skeleton  string
}

// AppendEvent：追加一条事件。并发取号靠 `UPDATE ... RETURNING max_seq_id` 行锁（§5.1），
// 杜绝「SELECT MAX+1 再 INSERT」在 READ COMMITTED 下的同号冲突。
func (s BundlesStore) AppendEvent(ctx context.Context, in AppendInput) (AppendResult, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return AppendResult{}, fmt.Errorf("开启事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var status string
	var participantIDs []string
	var initiatorID string
	var baseRev, keyVer int
	err = tx.QueryRow(ctx, `
		SELECT status, participant_uids, initiator_id, base_revision, key_version
		FROM bundles WHERE bundle_id = $1 FOR UPDATE`, in.BundleID).
		Scan(&status, &participantIDs, &initiatorID, &baseRev, &keyVer)
	if err != nil {
		if isNoRows(err) {
			return AppendResult{}, ErrBundleNotFound
		}
		return AppendResult{}, fmt.Errorf("锁定 bundle 失败: %w", err)
	}

	// 1) 成员 ACL（§1.7 第 3 条：包内放行，不要求 B↔C 互为好友）
	if !contains(participantIDs, in.SenderID) {
		return AppendResult{}, ErrNotParticipant
	}

	// 2) 已敲定不可再提交（REOPEN 由发起人在别处开闸，此处一律拦）
	if status == "CONFIRMED" || status == "CANCELLED" || status == "EXPIRED" {
		return AppendResult{}, ErrBundleConfirmed
	}

	// 3) 流水配额
	var events int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM team_schedule_events WHERE bundle_id = $1`, in.BundleID).Scan(&events); err != nil {
		return AppendResult{}, fmt.Errorf("统计流水失败: %w", err)
	}
	if events >= MaxBundleEvents {
		return AppendResult{}, ErrEventQuota
	}

	// 4) 因果冲突：仅非事实动作校验 base_revision
	if in.ExpectRev != nil && !IsFactAction(in.Action) && *in.ExpectRev != baseRev {
		return AppendResult{}, ErrStaleRevision
	}

	// 5) 发起人专属动作
	if (in.Action == "FORCE_FINALIZE" || in.Action == "CANCEL") && initiatorID != in.SenderID {
		return AppendResult{}, ErrNotInitiator
	}

	// 6) 中途加人：并入成员清单并复检配额
	memberIDs := participantIDs
	if len(in.AddMembers) > 0 {
		merged := append([]string{}, participantIDs...)
		for _, m := range in.AddMembers {
			if !contains(merged, m) {
				merged = append(merged, m)
			}
		}
		if len(merged) > MaxBundleMembers {
			return AppendResult{}, ErrTooManyMembers
		}
		memberIDs = merged
	}

	if in.BumpKeyVer {
		keyVer++
	}

	skeletonID, err := currentSkeleton(ctx, tx, in.BundleID)
	if err != nil {
		return AppendResult{}, err
	}
	if len(in.Topology) > 0 {
		var newID string
		if err := tx.QueryRow(ctx, `
			INSERT INTO bundle_skeletons (bundle_id, topology, quorum, version)
			SELECT bundle_id, $2, quorum, version + 1 FROM bundle_skeletons WHERE skeleton_id = $1
			RETURNING skeleton_id`, skeletonID, in.Topology).Scan(&newID); err != nil {
			return AppendResult{}, fmt.Errorf("推进骨架失败: %w", err)
		}
		skeletonID = newID
	}

	for _, e := range in.Envelopes {
		if _, err := tx.Exec(ctx, `
			INSERT INTO bundle_members (bundle_id, user_id, encrypted_bundle_key, key_ver)
			VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
			in.BundleID, e.RecipientUserID, e.WrappedKey, e.KeyVer); err != nil {
			return AppendResult{}, fmt.Errorf("落成员信封失败: %w", err)
		}
	}

	seq, err := takeSeq(ctx, tx, in.BundleID)
	if err != nil {
		return AppendResult{}, err
	}

	newStatus := status
	if in.SetStatus != "" {
		newStatus = in.SetStatus
	}
	if _, err := tx.Exec(ctx, `
		UPDATE bundles
		SET status = $2, key_version = $3, participant_uids = $4, updated_at = now()
		WHERE bundle_id = $1`, in.BundleID, newStatus, keyVer, memberIDs); err != nil {
		return AppendResult{}, fmt.Errorf("推进 bundle 状态失败: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO team_schedule_events (bundle_id, seq_id, action_type, sender_user_id, cipher, topology_ref, client_msg_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		in.BundleID, seq, in.Action, in.SenderID, in.Cipher, skeletonID, in.ClientMsgID); err != nil {
		return AppendResult{}, fmt.Errorf("写入事件失败: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return AppendResult{}, fmt.Errorf("提交事务失败: %w", err)
	}
	return AppendResult{SeqID: seq, Status: newStatus, KeyVer: keyVer, Skeleton: skeletonID}, nil
}

// takeSeq：行锁原子自增取号（§5.1 定稿写法）。
func takeSeq(ctx context.Context, tx pgx.Tx, bundleID string) (int64, error) {
	var seq int64
	if err := tx.QueryRow(ctx, `
		UPDATE bundles SET max_seq_id = max_seq_id + 1, updated_at = now()
		WHERE bundle_id = $1 RETURNING max_seq_id`, bundleID).Scan(&seq); err != nil {
		return 0, fmt.Errorf("取 seq 失败: %w", err)
	}
	return seq, nil
}

func currentSkeleton(ctx context.Context, tx pgx.Tx, bundleID string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		SELECT skeleton_id FROM bundle_skeletons
		WHERE bundle_id = $1 ORDER BY version DESC, created_at DESC LIMIT 1`, bundleID).Scan(&id)
	if err != nil {
		if isNoRows(err) {
			return "", nil
		}
		return "", fmt.Errorf("查询骨架失败: %w", err)
	}
	return id, nil
}

func contains(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// IsAcceptedFriend：PROPOSE 准入严管——发起人与每个被邀请人必须双向 accepted（§1.7）。
func (s BundlesStore) IsAcceptedFriend(ctx context.Context, a, b string) (bool, error) {
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

// BundleInfo：供 participating / sync 使用（Phase 1.5 接入）。
type BundleInfo struct {
	BundleID   string
	Status     string
	Lifecycle  string
	MaxSeqID   int64
	ExpiresAt  time.Time
	Members    []string
}

func (s BundlesStore) Get(ctx context.Context, bundleID string) (BundleInfo, bool, error) {
	var b BundleInfo
	err := s.Pool.QueryRow(ctx, `
		SELECT bundle_id, status, lifecycle, max_seq_id, expires_at, participant_uids
		FROM bundles WHERE bundle_id = $1`, bundleID).
		Scan(&b.BundleID, &b.Status, &b.Lifecycle, &b.MaxSeqID, &b.ExpiresAt, &b.Members)
	if err != nil {
		if isNoRows(err) {
			return BundleInfo{}, false, nil
		}
		return BundleInfo{}, false, fmt.Errorf("查询 bundle 失败: %w", err)
	}
	return b, true, nil
}
