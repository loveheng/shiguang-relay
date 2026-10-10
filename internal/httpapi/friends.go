package httpapi

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"shiguang-relay/internal/apierr"
	"shiguang-relay/internal/auth"
	"shiguang-relay/internal/store"
)

// 好友域（协同设计 §1.6 + Plan A 用户名搜索双通道）：
//   - 扫码路径：禁止拿纯 user_id 全局发申请（防撞库骚扰）—— 必须凭对方签发的一次性 Ticket；
//   - 搜索路径：A 以 Bearer 身份凭 user_id 直发（用户名本身即发现通道），防滥用靠
//     限流 + 接收方待审批配额 ≤50 + 关系去重 409 + 接收方可拉黑；
//   - 两路殊途同归：同样落 friendships(a=发起人, b=接收人, pending)，被邀方手动 approve；
//   - 服务端看不到 encrypted_intro 明文（端侧 ECIES，密钥经 lookup/prekey 取对方公钥）。

type ticketReq struct {
	IssuerUserID  string `json:"issuer_user_id"`
	SubjectUserID string `json:"subject_user_id"`
	Nonce         string `json:"nonce"`
	ExpiresAt     int64  `json:"expires_at"`
	Signature     string `json:"signature"`
	EncKeyPub     string `json:"enc_key_pub"`
}

type inviteReq struct {
	Ticket         ticketReq `json:"ticket"`
	EncryptedIntro string    `json:"encrypted_intro"`
}

type acceptReq struct {
	InviteID string `json:"invite_id"`
	Accept   bool   `json:"accept"`
}

// friendRequestReq：用户名搜索路径的好友申请（无 Ticket——A 以 Bearer 身份直发）。
type friendRequestReq struct {
	ToUserID       string `json:"to_user_id"`
	EncryptedIntro string `json:"encrypted_intro"`
}

// handleFriendRequest：POST /v1/friends/request —— 用户名搜索路径直发申请。
// 与扫码 Ticket 路径殊途同归：同样落 friendships(a=发起人, b=接收人, pending)。
func (d Deps) handleFriendRequest(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserIDFromContext(r.Context())
	if caller == "" {
		apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized, "missing bearer access token", nil)
		return
	}

	allowed, _, err := d.Limiter.Allow(r.Context(), "friend_request", caller)
	if err != nil {
		allowed = true // Redis 抖动放行（限流非最后一道防线）
	}
	if !allowed {
		apierr.Write(w, http.StatusTooManyRequests, apierr.RateLimited,
			"too many friend requests", map[string]any{"limit_per_min": d.FriendInviteLimitPerMin})
		return
	}

	var req friendRequestReq
	if !decode(w, r, &req) {
		return
	}
	if req.ToUserID == "" || req.ToUserID == caller {
		apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "invalid to_user_id", nil)
		return
	}

	// 目标必须存在（公钥存在性兼检查，FK 违例不该走到 500）
	pub, err := d.Identities.IdentityKey(r.Context(), req.ToUserID)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "identity lookup failure", nil)
		return
	}
	if len(pub) == 0 {
		apierr.Write(w, http.StatusNotFound, apierr.UserNotFound, "unknown user", nil)
		return
	}

	// 接收方待审批配额（与 Ticket 路径同口径，防灌爆 Pending）
	pending, err := d.Friends.CountPendingInvolving(r.Context(), req.ToUserID)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "pending count failure", nil)
		return
	}
	if pending >= store.MaxPendingInvites {
		apierr.Write(w, http.StatusBadRequest, apierr.ExceedPendingInvites,
			"too many pending invites for this user", map[string]any{"limit": store.MaxPendingInvites})
		return
	}

	// intro：A 用 lookup/prekey 取得的 B 公钥 ECIES 加密，服务端纯盲；可缺省
	intro, err := base64.StdEncoding.DecodeString(req.EncryptedIntro)
	if err != nil {
		intro = nil
	}
	if err := d.Friends.CreatePending(r.Context(), caller, req.ToUserID, intro); err != nil {
		if errors.Is(err, store.ErrRelationExists) {
			apierr.Write(w, http.StatusConflict, apierr.RelationExists, "relation already exists", nil)
			return
		}
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to create friend request", nil)
		return
	}

	apierr.WriteJSON(w, http.StatusCreated, map[string]any{
		"invite_id": makeInviteID(caller, req.ToUserID),
		"status":    "pending",
	})
}

// inviteID 形态：`{user_id_a}:{user_id_b}`（friendships 主键就是这对 UUID，无需额外 invite 表）。
func makeInviteID(a, b string) string { return a + ":" + b }

func parseInviteID(s string) (a, b string, ok bool) {
	i := strings.Index(s, ":")
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

func (d Deps) handleInviteFriend(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserIDFromContext(r.Context())
	if caller == "" {
		apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized, "missing bearer access token", nil)
		return
	}

	allowed, _, err := d.Limiter.Allow(r.Context(), "friend_invite", caller)
	if err != nil {
		allowed = true // Redis 抖动放行（限流非最后一道防线）
	}
	if !allowed {
		apierr.Write(w, http.StatusTooManyRequests, apierr.RateLimited,
			"too many friend invites", map[string]any{"limit_per_min": d.FriendInviteLimitPerMin})
		return
	}

	var req inviteReq
	if !decode(w, r, &req) {
		return
	}
	t := req.Ticket

	// 1) 签发人必须存在（取 Ed25519 身份公钥验签）
	if t.IssuerUserID == "" || t.IssuerUserID == caller {
		apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "invalid ticket issuer", nil)
		return
	}
	if t.SubjectUserID != "" && t.SubjectUserID != caller {
		apierr.Write(w, http.StatusForbidden, apierr.TicketSubjectInvalid,
			"ticket is bound to another subject", nil)
		return
	}
	issuerPub, err := d.Identities.IdentityKey(r.Context(), t.IssuerUserID)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "identity lookup failure", nil)
		return
	}
	if len(issuerPub) == 0 {
		apierr.Write(w, http.StatusNotFound, apierr.UserNotFound, "unknown ticket issuer", nil)
		return
	}

	// 2) 验签 + 过期（规范化消息口径见 auth.TicketMessage）
	sig, err := base64.StdEncoding.DecodeString(t.Signature)
	if err != nil {
		apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "ticket signature must be base64", nil)
		return
	}
	ticket := auth.FriendshipTicket{
		IssuerUserID:  t.IssuerUserID,
		SubjectUserID: t.SubjectUserID,
		Nonce:         t.Nonce,
		ExpiresAt:     t.ExpiresAt,
		Signature:     sig,
	}
	sigOK, expired := auth.VerifyFriendshipTicket(issuerPub, ticket)
	if !sigOK {
		apierr.Write(w, http.StatusUnauthorized, apierr.TicketSigInvalid, "ticket signature invalid", nil)
		return
	}
	if expired {
		apierr.Write(w, http.StatusBadRequest, apierr.TicketExpired, "ticket expired", nil)
		return
	}

	// 3) nonce 一次性（重放旧名片无效）
	claimed, err := d.Challenges.ClaimTicketNonce(r.Context(), t.IssuerUserID, t.Nonce, t.ExpiresAt)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "nonce store failure", nil)
		return
	}
	if !claimed {
		apierr.Write(w, http.StatusBadRequest, apierr.TicketNonceUsed, "ticket nonce already used", nil)
		return
	}

	// 4) 待审批邀请配额（§10.4 ≤50，防扫码灌爆 Pending）
	pending, err := d.Friends.CountPendingInvolving(r.Context(), t.IssuerUserID)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "pending count failure", nil)
		return
	}
	if pending >= store.MaxPendingInvites {
		apierr.Write(w, http.StatusBadRequest, apierr.ExceedPendingInvites,
			"too many pending invites for this user", map[string]any{"limit": store.MaxPendingInvites})
		return
	}

	// 5) 落 pending（intro 端侧密文，服务端只当字节存放）
	intro, err := base64.StdEncoding.DecodeString(req.EncryptedIntro)
	if err != nil {
		intro = nil // 自报家门可缺省；不因此拒绝建联
	}
	if err := d.Friends.CreatePending(r.Context(), caller, t.IssuerUserID, intro); err != nil {
		if errors.Is(err, store.ErrRelationExists) {
			apierr.Write(w, http.StatusConflict, apierr.RelationExists, "relation already exists", nil)
			return
		}
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to create invite", nil)
		return
	}

	apierr.WriteJSON(w, http.StatusCreated, map[string]any{
		"invite_id": makeInviteID(caller, t.IssuerUserID),
		"status":    "pending",
	})
}

func (d Deps) handleAcceptFriend(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserIDFromContext(r.Context())
	if caller == "" {
		apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized, "missing bearer access token", nil)
		return
	}
	var req acceptReq
	if !decode(w, r, &req) {
		return
	}
	a, b, ok := parseInviteID(req.InviteID)
	if !ok {
		apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "malformed invite_id", nil)
		return
	}
	if b != caller {
		// 只有被邀方能处置——发起人自己批准自己的申请不成立
		apierr.Write(w, http.StatusForbidden, apierr.InviteNotFound, "invite not addressable by caller", nil)
		return
	}
	if err := d.Friends.Respond(r.Context(), caller, a, b, req.Accept); err != nil {
		if errors.Is(err, store.ErrInviteNotFound) {
			apierr.Write(w, http.StatusNotFound, apierr.InviteNotFound, "pending invite not found", nil)
			return
		}
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to respond invite", nil)
		return
	}
	status := "blocked"
	if req.Accept {
		status = "accepted"
	}
	apierr.WriteJSON(w, http.StatusOK, map[string]any{"user_id": a, "status": status})
}

func (d Deps) handleListFriends(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserIDFromContext(r.Context())
	if caller == "" {
		apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized, "missing bearer access token", nil)
		return
	}
	rows, err := d.Friends.List(r.Context(), caller)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to list friends", nil)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, f := range rows {
		item := map[string]any{
			"user_id":    f.UserID,
			"username":   f.Username,
			"status":     f.Status,
			"created_at": f.CreatedAt.Unix(),
		}
		// 自报家门只在「我是被邀方 + 仍 pending」时回包（A 自己也解不开）
		if f.Status == "pending" && f.AmInvitee && len(f.EncryptedIntro) > 0 {
			item["encrypted_intro"] = base64.StdEncoding.EncodeToString(f.EncryptedIntro)
		}
		out = append(out, item)
	}
	apierr.WriteJSON(w, http.StatusOK, map[string]any{"friends": out})
}

// handleRemoveFriend：DELETE /v1/friends/{user_id} —— 解除关系（删除好友 / 撤回申请 / 解除拉黑）。
// 双向命中、行级删除；双方回到可重新申请状态。无关系 → 404（与 invite 不可达同一错误码族）。
func (d Deps) handleRemoveFriend(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserIDFromContext(r.Context())
	if caller == "" {
		apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized, "missing bearer access token", nil)
		return
	}
	peer := r.PathValue("user_id")
	if peer == "" || peer == caller {
		apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "invalid user_id", nil)
		return
	}
	if err := d.Friends.Remove(r.Context(), caller, peer); err != nil {
		if errors.Is(err, store.ErrRelationNotFound) {
			apierr.Write(w, http.StatusNotFound, apierr.InviteNotFound, "no such relation", nil)
			return
		}
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to remove relation", nil)
		return
	}
	apierr.WriteJSON(w, http.StatusOK, map[string]any{"user_id": peer, "status": "removed"})
}

// handleBlockFriend：POST /v1/friends/{user_id}/block —— 主动拉黑（对称化补全：此前只能被动拒绝）。
// 无需既有关系；pending/accepted 一并转 blocked。防滥用 = 限流 + 拉黑列表配额（blocked 行也是存储）。
func (d Deps) handleBlockFriend(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserIDFromContext(r.Context())
	if caller == "" {
		apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized, "missing bearer access token", nil)
		return
	}
	peer := r.PathValue("user_id")
	if peer == "" || peer == caller {
		apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "invalid user_id", nil)
		return
	}
	allowed, _, err := d.Limiter.Allow(r.Context(), "friend_request", caller)
	if err != nil {
		allowed = true // Redis 抖动放行（限流非最后一道防线）
	}
	if !allowed {
		apierr.Write(w, http.StatusTooManyRequests, apierr.RateLimited,
			"too many friend requests", map[string]any{"limit_per_min": d.FriendInviteLimitPerMin})
		return
	}
	// 目标必须存在（与申请路径同口径）
	pub, err := d.Identities.IdentityKey(r.Context(), peer)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "identity lookup failure", nil)
		return
	}
	if len(pub) == 0 {
		apierr.Write(w, http.StatusNotFound, apierr.UserNotFound, "unknown user", nil)
		return
	}
	// 拉黑列表存储配额（防灌爆；与 Pending ≤50 同思路）
	if n, err := d.Friends.CountBlockedBy(r.Context(), caller); err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "blocked count failure", nil)
		return
	} else if n >= store.MaxBlockedRelations {
		apierr.Write(w, http.StatusBadRequest, apierr.ExceedBlockedList,
			"block list quota exceeded", map[string]any{"limit": store.MaxBlockedRelations})
		return
	}
	if err := d.Friends.Block(r.Context(), caller, peer); err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to block user", nil)
		return
	}
	apierr.WriteJSON(w, http.StatusOK, map[string]any{"user_id": peer, "status": "blocked"})
}
