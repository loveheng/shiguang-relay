// Package apierr：统一错误响应体（协同设计 §10.4）。
// 铁律：message 恒为服务端固定英文串，detail 只放 UUID/seq 等结构值——错误通道同样过零知识审计。
package apierr

import (
	"encoding/json"
	"net/http"
)

// 错误码（§10.4 字典族；本文件只增 Phase 1 在用的码，后续 Phase 补齐时统一在此登记）
const (
	InvalidRequest       = "INVALID_REQUEST"
	Unauthorized         = "UNAUTHORIZED"
	ChallengeInvalid     = "CHALLENGE_INVALID"
	PopSignatureInvalid  = "POP_SIGNATURE_INVALID"
	PowSolutionInvalid   = "POW_SOLUTION_INVALID"
	UserAlreadyExists    = "USER_ALREADY_EXISTS"
	UserNotFound         = "USER_NOT_FOUND"
	UsernameRequired     = "USERNAME_REQUIRED"
	UsernameInvalid      = "USERNAME_INVALID"
	UsernameExists       = "USERNAME_EXISTS"
	PasswordTooWeak      = "PASSWORD_TOO_WEAK"
	UserOrPasswordInvalid = "USER_OR_PASSWORD_INVALID"
	PasswordMismatch     = "PASSWORD_MISMATCH"
	RateLimited          = "RATE_LIMITED"
	LoginThrottled       = "LOGIN_THROTTLED"
	TokenStale           = "TOKEN_STALE"    // 改密后旧会话（纪元落后）
	TokenRevoked         = "TOKEN_REVOKED"  // jti 已拉黑（rotation 重用 / 登出）
	PreKeyCountInvalid   = "PREKEY_COUNT_INVALID"
	// 好友域（§10.4 字典族 + §1.6）
	TicketExpired        = "TICKET_EXPIRED"
	TicketSigInvalid     = "TICKET_SIGNATURE_INVALID"
	TicketNonceUsed      = "TICKET_NONCE_USED"
	TicketSubjectInvalid = "TICKET_SUBJECT_INVALID"
	ExceedPendingInvites = "EXCEED_PENDING_INVITES"
	ExceedBlockedList    = "EXCEED_BLOCKED_LIST"
	RelationExists       = "RELATION_EXISTS"
	InviteNotFound       = "INVITE_NOT_FOUND"
	// 协同动作（§10.4 字典族）
	BundleNotFound      = "BUNDLE_NOT_FOUND"
	NotParticipant      = "NOT_PARTICIPANT"
	NotInitiator        = "NOT_INITIATOR"
	BundleConfirmedImmu = "BUNDLE_CONFIRMED_IMMUTABLE"
	StaleRevision       = "STALE_REVISION"
	EventQuotaExceeded  = "EVENT_QUOTA_EXCEEDED"
	ExceedMaxMembers    = "EXCEED_MAX_MEMBERS"
	ExceedActiveBundles = "EXCEED_ACTIVE_BUNDLES"
	UnknownAction       = "UNKNOWN_ACTION"
	RecipientNotFriend  = "RECIPIENT_NOT_FRIEND"
	PayloadOversize      = "ATTACHMENT_OVERSIZE"
	MethodNotAllowed     = "METHOD_NOT_ALLOWED"
	NotImplemented       = "NOT_IMPLEMENTED"
	Internal             = "INTERNAL_ERROR"
)

// Body：统一响应体。
type Body struct {
	ErrorCode string         `json:"error_code"`
	Message   string         `json:"message"`
	Detail    map[string]any `json:"detail,omitempty"`
}

// Write：以给定状态码写出统一错误体。
func Write(w http.ResponseWriter, status int, code, message string, detail map[string]any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Body{ErrorCode: code, Message: message, Detail: detail})
}

// WriteJSON：写出正常 JSON 响应体。
func WriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
