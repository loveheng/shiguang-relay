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
	MaxBundleMembers = 16 // 单 Bundle 成员数（可配放宽至 32）
	MaxActiveBundles = 20 // 单用户活跃方案包
	MaxBundleEvents  = 2000
	DefaultBundleTTL = 14 * 24 * time.Hour
)

// 事实三动作：显式豁免 base_revision 乐观锁（v0.1.3，§5.4 案A 拍板维持）——不校验、不自增，
// 仅取 seq，防假性冲突惊群。
var factActions = map[string]bool{
	"ATTACH_FACT": true,
	"UPDATE_FACT": true,
	"DETACH_FACT": true,
}

// IsFactAction：事实挂载类动作不参与因果冲突判定，也不推进 bundle 结构版本。
func IsFactAction(action string) bool { return factActions[action] }

// terminalGateOpen：终态门禁白名单（§4.3/§4.4/§4.5，2026-10-25 拍板）——仅这三个非终态动作
// 在 CONFIRMED 态放行；CANCELLED/EXPIRED 一律拦（REOPEN 亦不可从取消/过期拉回）。
// PATCH_STEP_TIME=敲定后单步骤改期轻通道；LEAVE=成员自主退出；REOPEN=紧急退回（CONFIRMED→STALLED）。
func terminalGateOpen(action string) bool {
	switch action {
	case "PATCH_STEP_TIME", "LEAVE", "REOPEN":
		return true
	}
	return false
}

var (
	ErrBundleNotFound  = errors.New("bundle not found")
	ErrNotParticipant  = errors.New("sender is not a participant of bundle")
	ErrNotInitiator    = errors.New("only the initiator may perform this action")
	ErrInitiatorLeave  = errors.New("initiator cannot leave; transfer ownership first")
	ErrBundleConfirmed = errors.New("bundle already confirmed")
	// ErrReopenInvalidState：REOPEN 仅 CONFIRMED 态放行（v0.1.10，§4.3/§4.4 转移行唯一来源）。
	ErrReopenInvalidState = errors.New("reopen is only allowed on confirmed bundles")
	ErrStaleRevision      = errors.New("stale base revision")
	ErrEventQuota         = errors.New("bundle event quota exceeded")
	ErrTooManyMembers     = errors.New("too many bundle members")
	ErrTooManyBundles     = errors.New("too many active bundles")
)

type MemberKeyEnvelope struct {
	RecipientUserID string `json:"recipient_user_id"`
	WrappedKey      []byte `json:"wrapped_key"`
	KeyVer          int    `json:"key_ver"`
}

type ProposeInput struct {
	InitiatorID    string
	ProposalType   string
	ParticipantIDs []string
	ExpiresAt      time.Time
	EncryptedMeta  []byte
	Topology       json.RawMessage
	Quorum         int
	Envelopes      []MemberKeyEnvelope
	Action         string
	Cipher         []byte
	ClientMsgID    string
}

type ProposeResult struct {
	BundleID   string
	SkeletonID string
	SeqID      int64
	Status     string
	ExpiresAt  time.Time
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
	BundleID      string
	SenderID      string
	Action        string
	Cipher        []byte
	ClientMsgID   string
	Topology      json.RawMessage // 结构变更类动作携带的新骨架（PATCH/PRUNE/REASSIGN/ADD_MEMBER）
	Envelopes     []MemberKeyEnvelope
	ExpectRev     *int     // 发起人整体重构时的因果校验（事实三动作豁免）
	SetStatus     string   // 终态动作：CONFIRMED / CANCELLED
	BumpKeyVer    bool     // REKEY
	AddMembers    []string // ADD_MEMBER：并入 participant_uids（发起人独占 + 双向 accepted 准入 + 配额复检）
	RemoveMembers []string // MEMBER_REMOVED（v0.1.10）：移出 participant_uids（发起人独占；信封行保留供离线回放）
	TransferTo    string   // TRANSFER_INITIATOR（v0.1.10）：新发起人明文 uid，须为包内成员
}

type AppendResult struct {
	SeqID    int64
	Status   string
	KeyVer   int
	Skeleton string
}

// AppendEvent：追加一条事件。并发取号靠 `UPDATE ... RETURNING max_seq_id` 行锁（§5.1），
// 杜绝「SELECT MAX+1 再 INSERT」在 READ COMMITTED 下的同号冲突。
func (s BundlesStore) AppendEvent(ctx context.Context, in AppendInput) (AppendResult, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return AppendResult{}, fmt.Errorf("开启事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var status, proposalType string
	var participantIDs []string
	var initiatorID string
	var baseRev, keyVer int
	err = tx.QueryRow(ctx, `
		SELECT status, proposal_type, participant_uids, initiator_id, base_revision, key_version
		FROM bundles WHERE bundle_id = $1 FOR UPDATE`, in.BundleID).
		Scan(&status, &proposalType, &participantIDs, &initiatorID, &baseRev, &keyVer)
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

	// 2) 终态门禁（2026-10-25 拍板 §4.3/§4.4/§4.5）：CONFIRMED 后仅白名单三动作可过
	//    （PATCH_STEP_TIME 单步骤改期 / LEAVE 自主退出 / REOPEN 紧急退回）；
	//    CANCELLED/EXPIRED 一律拦。非终态态对白名单动作不设限（服务端盲校验不做
	//    状态推导 §4.1，语义由端侧 FSM 收口）。
	if status == "CANCELLED" || status == "EXPIRED" ||
		(status == "CONFIRMED" && !terminalGateOpen(in.Action)) {
		return AppendResult{}, ErrBundleConfirmed
	}

	// 2.1) REOPEN 仅 CONFIRMED 态放行（v0.1.10）：PROPOSED/STALLED 上重开无意义，
	//      直接 409 拦截（CANCELLED/EXPIRED 已被上方终态门禁以统一口径拦）。
	if in.Action == "REOPEN" && status != "CONFIRMED" {
		return AppendResult{}, ErrReopenInvalidState
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

	// 4) 因果冲突：仅非事实动作校验 base_revision（opt-in，§5.4 案A 2026-10-25 拍板）——
	//    仅当请求显式携带 expected_revision 才与当前值比对（客户端只在整体重构/结构变更类
	//    提交携带）；普通平权动作不携带、永不因版本互打回（防惊群）。
	if in.ExpectRev != nil && !IsFactAction(in.Action) && *in.ExpectRev != baseRev {
		return AppendResult{}, ErrStaleRevision
	}

	// 5) 发起人专属 / 发起人禁投动作（2026-10-25 拍板 + v0.1.10 补齐）：
	//    FORCE_FINALIZE / CANCEL / PATCH_STEP_TIME / ADD_MEMBER（§5.3.1 管理员=发起人）/
	//    MEMBER_REMOVED / TRANSFER_INITIATOR 发起人独占；LEAVE 发起人不可用——
	//    退出走 TRANSFER_INITIATOR，防包挂死在无主状态（§4.5）；
	//    REOPEN 权限按 proposal_type 分流：DIRECTIVE 发起人独占（§4.3 紧急退回）、
	//    CONSENSUS 包内平权（§4.4「临时有事，平权重开」）。
	initiatorOnly := in.Action == "FORCE_FINALIZE" || in.Action == "CANCEL" ||
		in.Action == "PATCH_STEP_TIME" || in.Action == "ADD_MEMBER" ||
		in.Action == "MEMBER_REMOVED" || in.Action == "TRANSFER_INITIATOR"
	if (initiatorOnly || (in.Action == "REOPEN" && proposalType == "DIRECTIVE")) && initiatorID != in.SenderID {
		return AppendResult{}, ErrNotInitiator
	}
	if in.Action == "LEAVE" && initiatorID == in.SenderID {
		return AppendResult{}, ErrInitiatorLeave
	}
	// TRANSFER_INITIATOR：新发起人必须是包内成员（服务端改写 initiator_id 必须见明文 uid）
	if in.Action == "TRANSFER_INITIATOR" && !contains(participantIDs, in.TransferTo) {
		return AppendResult{}, ErrNotParticipant
	}

	// 5.1) ADD_MEMBER 准入严管（v0.1.10，对齐 PROPOSE §1.7）：每个被加人与发起人双向 accepted，
	//      杜绝任意成员越权拉「发起人非好友」入包。
	if in.Action == "ADD_MEMBER" {
		for _, m := range in.AddMembers {
			ok, err := txIsAcceptedFriend(ctx, tx, initiatorID, m)
			if err != nil {
				return AppendResult{}, fmt.Errorf("好友校验失败: %w", err)
			}
			if !ok {
				return AppendResult{}, ErrNotParticipant
			}
		}
	}

	// 6) 成员清单变更：ADD_MEMBER 并入 / MEMBER_REMOVED 移出（均按动作分发，不接受脏复用）。
	memberIDs := append([]string{}, participantIDs...)
	if in.Action == "ADD_MEMBER" && len(in.AddMembers) > 0 {
		for _, m := range in.AddMembers {
			if !contains(memberIDs, m) {
				memberIDs = append(memberIDs, m)
			}
		}
	}
	if in.Action == "MEMBER_REMOVED" && len(in.RemoveMembers) > 0 {
		// 发起人自身不可被移出（防包无主；发起人退出走 TRANSFER_INITIATOR §4.5）——
		// 从移除集合中剔除发起人，而非把发起人放进移除集合。
		removed := map[string]bool{}
		for _, m := range in.RemoveMembers {
			if m != initiatorID {
				removed[m] = true
			}
		}
		filtered := memberIDs[:0]
		for _, m := range memberIDs {
			if !removed[m] {
				filtered = append(filtered, m)
			}
		}
		memberIDs = filtered
	}
	if len(memberIDs) > MaxBundleMembers {
		return AppendResult{}, ErrTooManyMembers
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
	// REOPEN 显式转移行（§4.3：CONFIRMED --发起人 REOPEN--> STALLED，v0.1.10 实装）：
	// 服务端仅按门禁白名单放行后落显式状态位，让普通动作重新可入——非状态推导。
	if in.Action == "REOPEN" && status == "CONFIRMED" {
		newStatus = "STALLED"
	}
	var initiatorTo *string
	if in.Action == "TRANSFER_INITIATOR" && in.TransferTo != "" {
		initiatorTo = &in.TransferTo
	}
	// base_revision= bundle 级结构版本（§5.4 案A）：每个非事实动作自增 1，事实三动作豁免；
	// 失败动作在上方各守卫处提前返回，不经过本自增（计数只记成功落流水的行为）。
	newBaseRev := baseRev
	if !IsFactAction(in.Action) {
		newBaseRev++
	}
	if _, err := tx.Exec(ctx, `
		UPDATE bundles
		SET status = $2, key_version = $3, participant_uids = $4,
		    initiator_id = COALESCE($5, initiator_id), base_revision = $6, updated_at = now()
		WHERE bundle_id = $1`, in.BundleID, newStatus, keyVer, memberIDs, initiatorTo, newBaseRev); err != nil {
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

// txIsAcceptedFriend：同上，但在 AppendEvent 事务内执行（与 bundle 行锁同事务，
// ADD_MEMBER 准入判定与成员合并原子生效）。
func txIsAcceptedFriend(ctx context.Context, tx pgx.Tx, a, b string) (bool, error) {
	var n int
	err := tx.QueryRow(ctx, `
		SELECT count(*) FROM friendships
		WHERE status = 'accepted'
		  AND ((user_id_a = $1 AND user_id_b = $2) OR (user_id_a = $2 AND user_id_b = $1))`, a, b).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// BundleInfo：供 participating / sync 使用（Phase 1.5 接入）。
type BundleInfo struct {
	BundleID  string
	Status    string
	Lifecycle string
	MaxSeqID  int64
	ExpiresAt time.Time
	Members   []string
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
