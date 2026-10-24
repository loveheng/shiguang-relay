package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	relayv1 "shiguang-relay/gen/go"
	"shiguang-relay/internal/apierr"
	"shiguang-relay/internal/auth"
	"shiguang-relay/internal/store"
)

// POST /v1/schedule/action（协同设计 §5.1 / §1.7 / §4.2）。
//
// 服务端可见面 = 动作枚举 + 拓扑骨架 + 成员 UUID；一切内容在 cipher 内，服务端零明文。
// 取号用行锁 `UPDATE ... RETURNING max_seq_id`（§5.1），杜绝 MAX+1 的并发同号冲突。

// actionTypes：与 relay_protocol.proto 的 ActionType 枚举保持同源（改动契约须同步此处）。
var actionTypes = map[string]bool{
	"PROPOSE": true, "ACCEPT": true, "REJECT": true, "PATCH_TIME": true,
	"REASSIGN": true, "MAKE_OPTIONAL": true, "PRUNE": true, "CANCEL": true,
	"REOPEN": true, "VOTE": true, "ADD_SLOT": true, "FORCE_FINALIZE": true,
	"NUDGE": true, "BYPASS": true, "REKEY": true, "MEMBER_REMOVED": true,
	"TRANSFER_INITIATOR": true, "BRIEFING_UPDATE": true, "STEP_NOTE": true,
	"ATTACH_FACT": true, "UPDATE_FACT": true, "DETACH_FACT": true,
	"FREEMASK_QUERY": true, "FREEMASK_RESPONSE": true,
	"DELIVERY_ACK": true, "CLIENT_ACK": true, "PING": true, "ADD_MEMBER": true,
	"PATCH_STEP_TIME": true, "LEAVE": true,
}

// Broadcaster：事件广播。Phase 1.6 实装 WSS Hub；当前为内存空实现（接口先立，逻辑后补）。
type Broadcaster interface {
	Publish(bundleID string, seqID int64, action, sender string)
}

// RelayPusher：瞬时信令在线直推（v0.1.8，所有 kind 通用）。nil 容忍——单测可不注入，
// 届时退化为纯 REST 拉取（发单响应 delivered_online=false）。
type RelayPusher interface {
	PushRelay(userID string, msg *relayv1.RelayMessage) bool
}

type NoopBroadcaster struct{}

func (NoopBroadcaster) Publish(string, int64, string, string) {}

type envelopeReq struct {
	RecipientUserID string `json:"recipient_user_id"`
	WrappedKey      string `json:"wrapped_key"`
	KeyVer          int    `json:"key_ver"`
}

type actionReq struct {
	BundleID        string          `json:"bundle_id"`
	Action          string          `json:"action"`
	Cipher          string          `json:"cipher"`
	ProposalType    string          `json:"proposal_type"`
	ParticipantUIDs []string        `json:"participant_uids"`
	ExpiresAt       *int64          `json:"expires_at"`
	EncryptedMeta   string          `json:"encrypted_meta"`
	Topology        json.RawMessage `json:"topology"`
	Quorum          int             `json:"quorum"`
	Envelopes       []envelopeReq   `json:"member_key_envelopes"`
	ExpectedRev     *int            `json:"expected_revision"`
	AddMembers      []string        `json:"add_member_uids"`
	RemoveMembers   []string        `json:"remove_member_uids"` // MEMBER_REMOVED（v0.1.10）：明文被移除者
	TransferTo      string          `json:"transfer_to"`        // TRANSFER_INITIATOR（v0.1.10）：明文新发起人
}

func (d Deps) handleScheduleAction(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserIDFromContext(r.Context())
	if caller == "" {
		apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized, "missing bearer access token", nil)
		return
	}

	var req actionReq
	if !decode(w, r, &req) {
		return
	}
	if !actionTypes[req.Action] {
		apierr.Write(w, http.StatusBadRequest, apierr.UnknownAction, "unknown action_type", nil)
		return
	}
	cipher, err := base64.StdEncoding.DecodeString(req.Cipher)
	if err != nil {
		apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "cipher must be base64", nil)
		return
	}
	if len(cipher) == 0 {
		apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "cipher required", nil)
		return
	}

	envelopes, ok := decodeEnvelopes(w, req.Envelopes)
	if !ok {
		return
	}

	msgID := r.Header.Get(auth.HeaderClientMsgID)

	// 建包路径：bundle_id 缺省即 PROPOSE
	if req.BundleID == "" {
		if req.Action != "PROPOSE" {
			apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest,
				"bundle_id required for non-PROPOSE actions", nil)
			return
		}
		d.propose(w, r, caller, req, cipher, envelopes, msgID)
		return
	}

	appendIn := store.AppendInput{
		BundleID:      req.BundleID,
		SenderID:      caller,
		Action:        req.Action,
		Cipher:        cipher,
		ClientMsgID:   msgID,
		Topology:      req.Topology,
		Envelopes:     envelopes,
		ExpectRev:     req.ExpectedRev,
		AddMembers:    req.AddMembers,
		RemoveMembers: req.RemoveMembers,
		TransferTo:    req.TransferTo,
		BumpKeyVer:    req.Action == "REKEY",
	}
	switch req.Action {
	case "FORCE_FINALIZE":
		appendIn.SetStatus = "CONFIRMED"
	case "CANCEL":
		appendIn.SetStatus = "CANCELLED"
	case "TRANSFER_INITIATOR":
		// 服务端改写 bundles.initiator_id 必须见明文 uid（v0.1.10）；缺省即请求形状不合法
		if req.TransferTo == "" {
			apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "transfer_to required", nil)
			return
		}
	}

	res, err := d.Bundles.AppendEvent(r.Context(), appendIn)
	switch {
	case err == nil:
	case errors.Is(err, store.ErrBundleNotFound):
		apierr.Write(w, http.StatusNotFound, apierr.BundleNotFound, "unknown bundle", nil)
		return
	case errors.Is(err, store.ErrNotParticipant):
		apierr.Write(w, http.StatusForbidden, apierr.NotParticipant, "not a participant of this bundle", nil)
		return
	case errors.Is(err, store.ErrNotInitiator):
		apierr.Write(w, http.StatusForbidden, apierr.NotInitiator, "only initiator may perform this action", nil)
		return
	case errors.Is(err, store.ErrInitiatorLeave):
		apierr.Write(w, http.StatusForbidden, apierr.InitiatorCannotLeave, "initiator cannot leave; transfer ownership first", nil)
		return
	case errors.Is(err, store.ErrBundleConfirmed):
		apierr.Write(w, http.StatusConflict, apierr.BundleConfirmedImmu, "bundle is not open for actions", nil)
		return
	case errors.Is(err, store.ErrReopenInvalidState):
		apierr.Write(w, http.StatusConflict, apierr.ReopenInvalidState, "reopen is only allowed on confirmed bundles", nil)
		return
	case errors.Is(err, store.ErrStaleRevision):
		apierr.Write(w, http.StatusConflict, apierr.StaleRevision, "base revision conflict", nil)
		return
	case errors.Is(err, store.ErrEventQuota):
		apierr.Write(w, http.StatusBadRequest, apierr.EventQuotaExceeded, "bundle event quota exceeded", nil)
		return
	case errors.Is(err, store.ErrTooManyMembers):
		apierr.Write(w, http.StatusBadRequest, apierr.ExceedMaxMembers, "too many bundle members", nil)
		return
	default:
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to append event", nil)
		return
	}

	d.Broadcaster.Publish(req.BundleID, res.SeqID, req.Action, caller)
	apierr.WriteJSON(w, http.StatusOK, map[string]any{
		"bundle_id":  req.BundleID,
		"seq_id":     res.SeqID,
		"status":     res.Status,
		"key_ver":    res.KeyVer,
		"client_msg": msgID,
	})
}

func (d Deps) propose(w http.ResponseWriter, r *http.Request, caller string, req actionReq, cipher []byte, envelopes []store.MemberKeyEnvelope, msgID string) {
	participants := append([]string{caller}, req.ParticipantUIDs...)
	seen := map[string]bool{caller: true}
	uniq := []string{caller}
	for _, p := range req.ParticipantUIDs {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		uniq = append(uniq, p)
	}
	participants = uniq

	if len(participants) > store.MaxBundleMembers {
		apierr.Write(w, http.StatusBadRequest, apierr.ExceedMaxMembers,
			"too many bundle members", map[string]any{"limit": store.MaxBundleMembers})
		return
	}

	// 准入严管（§1.7）：PROPOSE 时发起人与每个被邀请人必须双向 accepted
	for _, p := range participants[1:] {
		ok, err := d.Bundles.IsAcceptedFriend(r.Context(), caller, p)
		if err != nil {
			apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "friendship check failure", nil)
			return
		}
		if !ok {
			apierr.Write(w, http.StatusForbidden, apierr.NotParticipant,
				"invitee is not an accepted friend", nil)
			return
		}
	}

	expires := time.Now().Add(store.DefaultBundleTTL)
	if req.ExpiresAt != nil {
		expires = time.Unix(*req.ExpiresAt, 0)
	}
	meta, _ := base64.StdEncoding.DecodeString(req.EncryptedMeta)
	ptype := req.ProposalType
	if ptype != "DIRECTIVE" && ptype != "CONSENSUS" {
		ptype = "CONSENSUS"
	}

	res, err := d.Bundles.Propose(r.Context(), store.ProposeInput{
		InitiatorID:    caller,
		ProposalType:   ptype,
		ParticipantIDs: participants,
		ExpiresAt:      expires,
		EncryptedMeta:  meta,
		Topology:       req.Topology,
		Quorum:         req.Quorum,
		Envelopes:      envelopes,
		Action:         req.Action,
		Cipher:         cipher,
		ClientMsgID:    msgID,
	})
	switch {
	case err == nil:
	case errors.Is(err, store.ErrTooManyMembers):
		apierr.Write(w, http.StatusBadRequest, apierr.ExceedMaxMembers, "too many bundle members", nil)
		return
	case errors.Is(err, store.ErrTooManyBundles):
		apierr.Write(w, http.StatusBadRequest, apierr.ExceedActiveBundles, "too many active bundles", nil)
		return
	default:
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to create bundle", nil)
		return
	}

	d.Broadcaster.Publish(res.BundleID, res.SeqID, req.Action, caller)
	apierr.WriteJSON(w, http.StatusCreated, map[string]any{
		"bundle_id":   res.BundleID,
		"skeleton_id": res.SkeletonID,
		"seq_id":      res.SeqID,
		"status":      res.Status,
	})
}

func decodeEnvelopes(w http.ResponseWriter, in []envelopeReq) ([]store.MemberKeyEnvelope, bool) {
	out := make([]store.MemberKeyEnvelope, 0, len(in))
	for _, e := range in {
		if e.RecipientUserID == "" {
			apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "envelope recipient required", nil)
			return nil, false
		}
		key, err := base64.StdEncoding.DecodeString(e.WrappedKey)
		if err != nil {
			apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "wrapped_key must be base64", nil)
			return nil, false
		}
		ver := e.KeyVer
		if ver <= 0 {
			ver = 1
		}
		out = append(out, store.MemberKeyEnvelope{RecipientUserID: e.RecipientUserID, WrappedKey: key, KeyVer: ver})
	}
	return out, true
}
