// Package httpapi：REST 路由与处理器装配。
// Phase 1.1 只落鉴权闭环（Challenge-Response + 双 Token + 幂等去重）；
// POST /v1/schedule/action 目前为 501 占位，Phase 1.4 收口。
package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"shiguang-relay/internal/apierr"
	"shiguang-relay/internal/auth"
	"shiguang-relay/internal/store"
)

const maxBodyBytes = 256 * 1024 // §10.4 单包硬限；超限 413

type Deps struct {
	Issuer      *auth.Issuer
	Challenges  *auth.ChallengeStore
	Idem        *auth.Idempotency
	Identities  auth.IdentityResolver
	PoWRequired bool // PoW 开关（本地联调可关；公网部署必须开）

	// Phase 1.2：注册与 PreKey 托管
	Users               store.UserStore
	Limiter             *auth.RateLimiter
	RegisterLimitPerMin int

	// Phase 1.3：好友域（Ticket 制建联）
	Friends                 store.FriendsStore
	FriendInviteLimitPerMin int
}

func NewRouter(d Deps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/healthz", func(w http.ResponseWriter, r *http.Request) {
		apierr.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "ts": time.Now().Unix()})
	})

	mux.Handle("POST /v1/auth/challenge", d.Idem.Wrap(http.HandlerFunc(d.handleChallenge)))
	mux.Handle("POST /v1/auth/login", d.Idem.Wrap(http.HandlerFunc(d.handleLogin)))
	mux.Handle("POST /v1/auth/refresh", d.Idem.Wrap(http.HandlerFunc(d.handleRefresh)))

	// Phase 1.2：注册（PoP 自签 + PoW + IP 限流）与 PreKey 托管
	mux.Handle("POST /v1/users", d.Idem.Wrap(http.HandlerFunc(d.handleRegister)))
	mux.Handle("GET /v1/users/{user_id}/prekey", d.Idem.Wrap(http.HandlerFunc(d.handleGetPreKey)))
	mux.Handle("POST /v1/users/me/prekeys",
		auth.RequireAuth(d.Issuer)(d.Idem.Wrap(http.HandlerFunc(d.handleRefillPreKeys))))

	// Phase 1.3：好友 Ticket 建联（全部要求 Bearer）
	mux.Handle("POST /v1/friends/invite",
		auth.RequireAuth(d.Issuer)(d.Idem.Wrap(http.HandlerFunc(d.handleInviteFriend))))
	mux.Handle("POST /v1/friends/accept",
		auth.RequireAuth(d.Issuer)(d.Idem.Wrap(http.HandlerFunc(d.handleAcceptFriend))))
	mux.Handle("GET /v1/friends",
		auth.RequireAuth(d.Issuer)(d.Idem.Wrap(http.HandlerFunc(d.handleListFriends))))

	// 受保护的业务路由：先 Bearer 鉴权，再幂等去重（顺序不可换——未鉴权流量不值得落缓存）
	mux.Handle("POST /v1/schedule/action",
		auth.RequireAuth(d.Issuer)(d.Idem.Wrap(http.HandlerFunc(d.handleScheduleAction))))

	// 兜底：未知路由一律 404 统一响应体，禁止 net/http 默认纯文本页（会漏出实现细节）
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		apierr.Write(w, http.StatusNotFound, "NOT_FOUND", "no such route", nil)
	})
	return mux
}

type challengeReq struct {
	UserID string `json:"user_id"`
}

type loginReq struct {
	UserID      string `json:"user_id"`
	Nonce       string `json:"nonce"`
	SignedPop   string `json:"signed_pop"`   // base64(Sign(nonce) with IK)
	PowSolution string `json:"pow_solution"`
}

type refreshReq struct {
	RefreshToken string `json:"refresh_token"`
}

func (d Deps) handleChallenge(w http.ResponseWriter, r *http.Request) {
	var req challengeReq
	if !decode(w, r, &req) {
		return
	}
	if req.UserID == "" {
		apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "user_id required", nil)
		return
	}
	ch, err := d.Challenges.Issue(r.Context(), req.UserID)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to issue challenge", nil)
		return
	}
	apierr.WriteJSON(w, http.StatusOK, ch)
}

func (d Deps) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if !decode(w, r, &req) {
		return
	}
	userID, pow, ok, err := d.Challenges.Consume(r.Context(), req.Nonce)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "challenge store failure", nil)
		return
	}
	if !ok {
		apierr.Write(w, http.StatusUnauthorized, apierr.ChallengeInvalid, "unknown or expired nonce", nil)
		return
	}
	if !auth.EqualID(userID, req.UserID) {
		apierr.Write(w, http.StatusUnauthorized, apierr.ChallengeInvalid, "nonce bound to another user", nil)
		return
	}
	if d.PoWRequired && !auth.VerifyPoW(pow, req.PowSolution, d.Challenges.Difficulty()) {
		apierr.Write(w, http.StatusUnauthorized, apierr.PowSolutionInvalid, "proof of work solution invalid", nil)
		return
	}

	pub, err := d.Identities.IdentityKey(r.Context(), req.UserID)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "identity lookup failure", nil)
		return
	}
	if len(pub) == 0 {
		apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized, "unknown user", nil)
		return
	}
	sig, err := base64.StdEncoding.DecodeString(req.SignedPop)
	if err != nil || !auth.VerifyPoP(pub, sig, req.Nonce) {
		apierr.Write(w, http.StatusUnauthorized, apierr.PopSignatureInvalid, "proof of possession signature invalid", nil)
		return
	}

	pair, err := d.Issuer.Issue(req.UserID)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to issue tokens", nil)
		return
	}
	apierr.WriteJSON(w, http.StatusOK, pair)
}

func (d Deps) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req refreshReq
	if !decode(w, r, &req) {
		return
	}
	userID, err := d.Issuer.Verify(req.RefreshToken, "refresh")
	if err != nil {
		apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized, "invalid or expired refresh token", nil)
		return
	}
	pair, err := d.Issuer.Issue(userID)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to issue tokens", nil)
		return
	}
	apierr.WriteJSON(w, http.StatusOK, pair)
}

func (d Deps) handleScheduleAction(w http.ResponseWriter, r *http.Request) {
	// Phase 1.4 收口：行锁取号 → 事务写 bundles/skeletons/流水 → 广播
	apierr.Write(w, http.StatusNotImplemented, apierr.NotImplemented,
		"schedule action lands in Phase 1.4", map[string]any{
			"user_id": auth.UserIDFromContext(r.Context()),
		})
}

// decode：限长解码请求体；任何解析失败都走统一 400/413。
func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			apierr.Write(w, http.StatusRequestEntityTooLarge, apierr.PayloadOversize,
				"request body exceeds 256KB", nil)
			return false
		}
		apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "malformed request body", nil)
		return false
	}
	return true
}
