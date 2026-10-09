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

// 好友域（协同设计 §1.6）：
//   - 禁止拿纯 user_id 全局发申请（防撞库骚扰）—— 必须凭对方签发的一次性 Ticket；
//   - 服务端只做「验签 + 过期 + nonce 一次性 + 配额」，看不到 encrypted_intro 明文（端侧 ECIES）；
//   - 客户端边界（§3.3）：pending 默认不自动接受，仅被邀方手动 approve。

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
