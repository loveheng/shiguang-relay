package httpapi

import (
	"encoding/base64"
	"net/http"
	"strconv"
	"time"

	"shiguang-relay/internal/apierr"
	"shiguang-relay/internal/auth"
)

// Phase 1.5：发现与同步（§10.2 / §10.3）——换机冷启动链路：
//   participating（发现我在哪些包里）→ sync（并发增量拉取）→ key-envelopes / vault（密钥还原）
// 外加 P2P 瞬时信令的 pending/ack（阅后即焚）。

func (d Deps) handleListParticipating(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserIDFromContext(r.Context())
	if caller == "" {
		apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized, "missing bearer access token", nil)
		return
	}
	lifecycle := r.URL.Query().Get("status")
	rows, err := d.Bundles.ListParticipating(r.Context(), caller, lifecycle)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to list bundles", nil)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, b := range rows {
		out = append(out, map[string]any{
			"bundle_id":      b.BundleID,
			"status":         b.Status,
			"lifecycle":      b.Lifecycle,
			"max_seq_id":     b.MaxSeqID,
			"last_acked_seq": b.LastAckedSeq,
			"expires_at":     b.ExpiresAt.Unix(),
			"updated_at":     b.UpdatedAt.Unix(),
			"initiator_id":   b.InitiatorID,
		})
	}
	apierr.WriteJSON(w, http.StatusOK, map[string]any{"bundles": out})
}

func (d Deps) handleSync(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserIDFromContext(r.Context())
	if caller == "" {
		apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized, "missing bearer access token", nil)
		return
	}
	q := r.URL.Query()
	bundleID := q.Get("bundle_id")
	if bundleID == "" {
		apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "bundle_id required", nil)
		return
	}
	since, _ := strconv.ParseInt(q.Get("since_seq"), 10, 64)
	if since < 0 {
		since = 0
	}
	limit, _ := strconv.Atoi(q.Get("limit"))

	ok, err := d.Bundles.IsParticipant(r.Context(), bundleID, caller)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "membership check failure", nil)
		return
	}
	if !ok {
		apierr.Write(w, http.StatusForbidden, apierr.NotParticipant, "not a participant of this bundle", nil)
		return
	}

	events, err := d.Bundles.EventsSince(r.Context(), bundleID, since, limit)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to fetch events", nil)
		return
	}
	out := make([]map[string]any, 0, len(events))
	var latest int64
	for _, e := range events {
		out = append(out, map[string]any{
			"seq_id":       e.SeqID,
			"action_type":  e.ActionType,
			"sender_id":    e.SenderID,
			"cipher":       base64.StdEncoding.EncodeToString(e.Cipher),
			"topology_ref": e.TopologyRef,
			"created_at":   e.CreatedAt.Unix(),
		})
		if e.SeqID > latest {
			latest = e.SeqID
		}
	}
	apierr.WriteJSON(w, http.StatusOK, map[string]any{
		"bundle_id":  bundleID,
		"events":     out,
		"latest_seq": latest,
		"has_more":   len(events) == cap(out) && len(events) > 0,
	})
}

func (d Deps) handleKeyEnvelopes(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserIDFromContext(r.Context())
	if caller == "" {
		apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized, "missing bearer access token", nil)
		return
	}
	bundleID := r.PathValue("bundle_id")
	ok, err := d.Bundles.IsParticipant(r.Context(), bundleID, caller)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "membership check failure", nil)
		return
	}
	if !ok {
		apierr.Write(w, http.StatusForbidden, apierr.NotParticipant, "not a participant of this bundle", nil)
		return
	}
	rows, err := d.Bundles.MemberKeyEnvelopes(r.Context(), bundleID, caller)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to load key envelopes", nil)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, rrow := range rows {
		out = append(out, map[string]any{
			"key_ver":     rrow.KeyVer,
			"wrapped_key": base64.StdEncoding.EncodeToString(rrow.WrappedKey),
			"created_at":  rrow.CreatedAt.Unix(),
		})
	}
	apierr.WriteJSON(w, http.StatusOK, map[string]any{"bundle_id": bundleID, "envelopes": out})
}

type vaultReq struct {
	BundleID    string `json:"bundle_id"`
	KeyVer      int    `json:"key_ver"`
	WrappedKeys string `json:"wrapped_keys"`
}

// handleVaultAppend：自我备份通道（§5.3）——Append-Only，同版本幂等不覆盖。
func (d Deps) handleVaultAppend(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserIDFromContext(r.Context())
	if caller == "" {
		apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized, "missing bearer access token", nil)
		return
	}
	var req vaultReq
	if !decode(w, r, &req) {
		return
	}
	if req.BundleID == "" || req.KeyVer <= 0 {
		apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "bundle_id and key_ver required", nil)
		return
	}
	blob, err := base64.StdEncoding.DecodeString(req.WrappedKeys)
	if err != nil || len(blob) == 0 {
		apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "wrapped_keys must be non-empty base64", nil)
		return
	}
	if err := d.Bundles.AppendVaultEnvelope(r.Context(), caller, req.BundleID, req.KeyVer, blob); err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to append envelope", nil)
		return
	}
	apierr.WriteJSON(w, http.StatusCreated, map[string]any{"bundle_id": req.BundleID, "key_ver": req.KeyVer})
}

func (d Deps) handleVaultList(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserIDFromContext(r.Context())
	if caller == "" {
		apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized, "missing bearer access token", nil)
		return
	}
	since, _ := strconv.Atoi(r.URL.Query().Get("since_version"))
	if since < 0 {
		since = 0
	}
	rows, err := d.Bundles.ListVaultEnvelopes(r.Context(), caller, since)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to list envelopes", nil)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, v := range rows {
		out = append(out, map[string]any{
			"bundle_id":    v.BundleID,
			"key_ver":      v.KeyVer,
			"wrapped_keys": base64.StdEncoding.EncodeToString(v.WrappedKeys),
			"created_at":   v.CreatedAt.Unix(),
		})
	}
	apierr.WriteJSON(w, http.StatusOK, map[string]any{"envelopes": out})
}

type relaySendReq struct {
	RecipientUserID string `json:"recipient_user_id"`
	Kind            string `json:"kind"`
	Cipher          string `json:"cipher"`
	TTLSeconds      int    `json:"ttl_seconds"`
}

// handleRelaySend：P2P 瞬时信令（非 bundle 事件）。§1.7 第 2 条：无 bundle 的直投信令必须双向好友。
func (d Deps) handleRelaySend(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserIDFromContext(r.Context())
	if caller == "" {
		apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized, "missing bearer access token", nil)
		return
	}
	var req relaySendReq
	if !decode(w, r, &req) {
		return
	}
	if req.RecipientUserID == "" {
		apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "recipient_user_id required", nil)
		return
	}
	if req.RecipientUserID == caller {
		apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "cannot relay to yourself", nil)
		return
	}
	ok, err := d.Friends.IsAcceptedFriend(r.Context(), caller, req.RecipientUserID)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "friendship check failure", nil)
		return
	}
	if !ok {
		apierr.Write(w, http.StatusForbidden, apierr.RecipientNotFriend, "recipient is not an accepted friend", nil)
		return
	}
	blob, err := base64.StdEncoding.DecodeString(req.Cipher)
	if err != nil || len(blob) == 0 {
		apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "cipher must be non-empty base64", nil)
		return
	}
	kind := req.Kind
	if kind == "" {
		kind = "generic"
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	id, err := d.Bundles.CreateRelayMessage(r.Context(), caller, req.RecipientUserID, kind, blob, ttl)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to store relay message", nil)
		return
	}
	apierr.WriteJSON(w, http.StatusAccepted, map[string]any{"msg_id": id})
}

func (d Deps) handleRelayPending(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserIDFromContext(r.Context())
	if caller == "" {
		apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized, "missing bearer access token", nil)
		return
	}
	msgs, err := d.Bundles.PendingRelayMessages(r.Context(), caller)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to list relay messages", nil)
		return
	}
	out := make([]map[string]any, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, map[string]any{
			"msg_id":     m.MsgID,
			"sender_id":  m.SenderID,
			"kind":       m.Kind,
			"cipher":     base64.StdEncoding.EncodeToString(m.Cipher),
			"expires_at": m.ExpiresAt.Unix(),
			"created_at": m.CreatedAt.Unix(),
		})
	}
	apierr.WriteJSON(w, http.StatusOK, map[string]any{"messages": out})
}

type relayAckReq struct {
	MessageIDs []string `json:"message_ids"`
}

func (d Deps) handleRelayAck(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserIDFromContext(r.Context())
	if caller == "" {
		apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized, "missing bearer access token", nil)
		return
	}
	var req relayAckReq
	if !decode(w, r, &req) {
		return
	}
	if len(req.MessageIDs) == 0 {
		apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "message_ids required", nil)
		return
	}
	n, err := d.Bundles.AckRelayMessages(r.Context(), caller, req.MessageIDs)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to ack relay messages", nil)
		return
	}
	apierr.WriteJSON(w, http.StatusOK, map[string]any{"acked": n})
}
