package httpapi

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"shiguang-relay/internal/apierr"
	"shiguang-relay/internal/auth"
	"shiguang-relay/internal/store"
)

// 注册与 PreKey 托管（协同设计 §1.5 / fact §7.1-2）。
//
// 三条 Sybil 防线在此合流：
//   1. PoP 自签（signed_pop）—— 请求方必须持有身份私钥，杜绝公钥置换；
//   2. PoW + 单 IP 限流 —— 挡批量刷号；
//   3. OPK 注册瘦身（首批 10~20）—— 即便刷进万号，单账号 DB 占用 <1KB。

type preKeyReq struct {
	KeyID     string `json:"key_id"`
	Pub       string `json:"pub"`
	Signature string `json:"signature"`
}

type registerReq struct {
	Username          string      `json:"username"`
	Password          string      `json:"password"`
	IdentityKeyPub    string      `json:"identity_key_pub"`
	SignedPrekeyPub   string      `json:"signed_prekey_pub"`
	SignedPrekeySig   string      `json:"signed_prekey_sig"`
	PushToken         string      `json:"push_token"`
	EncryptedProfile  string      `json:"encrypted_profile"`
	RecoveryVault     string      `json:"recovery_vault"`
	Nonce             string      `json:"nonce"`
	PowSolution       string      `json:"pow_solution"`
	OneTimePreKeys    []preKeyReq `json:"one_time_prekeys"`
}

// 用户名/密码策略（账号体系，与 E2EE 密钥解耦）：
//   - username：小写字母/数字/下划线，3~32；DB 唯一约束兜底
//   - password：明文仅走 TLS 传输，服务端零落库；最小长度 8
const (
	minUsernameLen = 3
	maxUsernameLen = 32
	minPasswordLen = 8
)

// validUsername：仅校验字符集与长度（大小写已在外层归一为小写）。
func validUsername(s string) bool {
	n := len(s)
	if n < minUsernameLen || n > maxUsernameLen {
		return false
	}
	for i := 0; i < n; i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

type refillReq struct {
	OneTimePreKeys []preKeyReq `json:"one_time_prekeys"`
}

func (d Deps) handleRegister(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	allowed, _, err := d.Limiter.Allow(r.Context(), "register", ip)
	if err != nil {
		// Redis 抖动：放行（可用性优先，限流不是最后一道防线）
		allowed = true
	}
	if !allowed {
		apierr.Write(w, http.StatusTooManyRequests, apierr.RateLimited,
			"too many registrations from this address", map[string]any{"limit_per_min": d.RegisterLimitPerMin})
		return
	}

	var req registerReq
	if !decode(w, r, &req) {
		return
	}

	// 1) 用户名/密码（账号体系，与 E2EE 密钥解耦）：归一小写 + 合法性 + 哈希（服务端零明文）
	username := strings.ToLower(strings.TrimSpace(req.Username))
	if !validUsername(username) {
		apierr.Write(w, http.StatusBadRequest, apierr.UsernameInvalid,
			"username must be 3-32 chars of lowercase letters/digits/underscore", nil)
		return
	}
	if len(req.Password) < minPasswordLen {
		apierr.Write(w, http.StatusBadRequest, apierr.PasswordTooWeak,
			"password too weak", map[string]any{"min_len": minPasswordLen})
		return
	}
	pwHash, err := auth.HashPassword(req.Password)
	if err != nil {
		slog.Error("密码哈希失败", "err", err)
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to hash password", nil)
		return
	}

	// 2) nonce：一次性消费（Challenge-Response，绑定 PoW 题面）
	_, pow, ok, err := d.Challenges.Consume(r.Context(), req.Nonce)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "challenge store failure", nil)
		return
	}
	if !ok {
		apierr.Write(w, http.StatusUnauthorized, apierr.ChallengeInvalid, "unknown or expired nonce", nil)
		return
	}

	// 3) PoW（仅挡最低级扫描；真防线=用户名唯一 + 单 IP 限流 + OPK 瘦身）
	if d.PoWRequired && !auth.VerifyPoW(pow, req.PowSolution, d.Challenges.Difficulty()) {
		apierr.Write(w, http.StatusUnauthorized, apierr.PowSolutionInvalid, "proof of work solution invalid", nil)
		return
	}

	// 4) E2EE 公钥材料（对用户透明，服务端纯盲存公钥）
	identityPub, err := base64.StdEncoding.DecodeString(req.IdentityKeyPub)
	if err != nil {
		apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "identity_key_pub must be base64", nil)
		return
	}
	spkPub, err := base64.StdEncoding.DecodeString(req.SignedPrekeyPub)
	if err != nil {
		apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "signed_prekey_pub must be base64", nil)
		return
	}
	spkSig, err := base64.StdEncoding.DecodeString(req.SignedPrekeySig)
	if err != nil {
		apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "signed_prekey_sig must be base64", nil)
		return
	}
	profile, _ := base64.StdEncoding.DecodeString(req.EncryptedProfile)
	vault, _ := base64.StdEncoding.DecodeString(req.RecoveryVault)

	// 5) OPK 瘦身：首批只允许 10~20
	if n := len(req.OneTimePreKeys); n < store.MinInitialPreKeys || n > store.MaxInitialPreKeys {
		apierr.Write(w, http.StatusBadRequest, apierr.PreKeyCountInvalid,
			"initial one-time prekeys out of allowed range", map[string]any{
				"min": store.MinInitialPreKeys, "max": store.MaxInitialPreKeys, "got": n,
			})
		return
	}
	keys, ok := decodePreKeys(w, req.OneTimePreKeys)
	if !ok {
		return
	}

	// 6) 单事务落用户（服务端生成 user_id）+ 首批 OPK
	userID, err := d.Users.CreateUserWithPreKeys(r.Context(), store.CreateUserInput{
		Username:         username,
		PasswordHash:     pwHash,
		IdentityKeyPub:   identityPub,
		SignedPrekeyPub:  spkPub,
		SignedPrekeySig:  spkSig,
		PushToken:        req.PushToken,
		EncryptedProfile: profile,
		RecoveryVault:    vault,
	}, keys)
	if errors.Is(err, store.ErrUsernameExists) {
		apierr.Write(w, http.StatusConflict, apierr.UsernameExists, "username already taken", nil)
		return
	}
	if errors.Is(err, store.ErrUserExists) {
		apierr.Write(w, http.StatusConflict, apierr.UserAlreadyExists, "user already registered", nil)
		return
	}
	if err != nil {
		// 细节只进服务端日志：错误通道零明文红线（§10.4）
		slog.Error("创建用户失败", "err", err, "username", username)
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to create user", nil)
		return
	}

	apierr.WriteJSON(w, http.StatusCreated, map[string]any{
		"user_id":   userID,
		"username":  username,
		"opk_count": len(keys),
	})
}

// handleGetPreKey：GET /v1/users/{user_id}/prekey —— 取 KeyBundle + 原子弹出 1 个 OPK。
// 空池恒 200（v0.1.6）：端侧降级 3-DH，服务端随行带 OPK_EMPTY_WARNING 提示。
func (d Deps) handleGetPreKey(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("user_id")
	bundle, found, err := d.Users.IdentityBundle(r.Context(), userID)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to load key bundle", nil)
		return
	}
	if !found {
		apierr.Write(w, http.StatusNotFound, apierr.UserNotFound, "unknown user", nil)
		return
	}

	resp := map[string]any{
		"user_id":            userID,
		"identity_key_pub":   b64(bundle.IdentityKeyPub),
		"signed_prekey_pub":  b64(bundle.SignedPrekeyPub),
		"signed_prekey_sig":  b64(bundle.SignedPrekeySig),
		"one_time_prekeys":   encodePreKeys(bundle.OneTimePreKeys),
		"remaining_opk":      bundle.RemainingOPK,
	}
	if bundle.RemainingOPK < store.LowPreKeyWatermark {
		resp["warning"] = "OPK_EMPTY_WARNING"
	}
	apierr.WriteJSON(w, http.StatusOK, resp)
}

// handleLookupUser：GET /v1/users/lookup?username= —— 用户名搜索（加好友「搜索」路径）。
// 仅登录用户可用（降低撞库/枚举面）；返回公钥身份，不弹出 OPK（X3DH 用 OPK 由调用方走 prekey 端点单独拉）。
func (d Deps) handleLookupUser(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserIDFromContext(r.Context())
	if caller == "" {
		apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized, "missing bearer access token", nil)
		return
	}
	// 限流防枚举（Redis 抖动放行；限流非最后一道防线）
	allowed, _, err := d.Limiter.Allow(r.Context(), "user_lookup", caller)
	if err != nil {
		allowed = true
	}
	if !allowed {
		apierr.Write(w, http.StatusTooManyRequests, apierr.RateLimited,
			"too many user lookups", map[string]any{"limit_per_min": d.FriendInviteLimitPerMin})
		return
	}
	username := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("username")))
	if !validUsername(username) {
		apierr.Write(w, http.StatusBadRequest, apierr.UsernameInvalid,
			"username must be 3-32 chars of lowercase letters/digits/underscore", nil)
		return
	}
	p, found, err := d.Users.PublicIdentityByUsername(r.Context(), username)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to lookup user", nil)
		return
	}
	if !found {
		apierr.Write(w, http.StatusNotFound, apierr.UserNotFound, "unknown user", nil)
		return
	}
	apierr.WriteJSON(w, http.StatusOK, map[string]any{
		"user_id":           p.UserID,
		"username":          p.Username,
		"identity_key_pub":  b64(p.IdentityKeyPub),
		"signed_prekey_pub": b64(p.SignedPrekeyPub),
		"signed_prekey_sig": b64(p.SignedPrekeySig),
	})
}

// handleRefillPreKeys：POST /v1/users/me/prekeys —— 低存量补仓（≤50/批）。
func (d Deps) handleRefillPreKeys(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	if userID == "" {
		apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized, "missing bearer access token", nil)
		return
	}
	var req refillReq
	if !decode(w, r, &req) {
		return
	}
	if n := len(req.OneTimePreKeys); n == 0 || n > store.MaxRefillPreKeys {
		apierr.Write(w, http.StatusBadRequest, apierr.PreKeyCountInvalid,
			"refill batch size out of allowed range", map[string]any{"max": store.MaxRefillPreKeys, "got": n})
		return
	}
	keys, ok := decodePreKeys(w, req.OneTimePreKeys)
	if !ok {
		return
	}
	if _, err := d.Users.InsertPreKeys(r.Context(), userID, keys); err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to refill prekeys", nil)
		return
	}
	total, err := d.Users.CountPreKeys(r.Context(), userID)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to count prekeys", nil)
		return
	}
	apierr.WriteJSON(w, http.StatusOK, map[string]any{"inserted": len(keys), "total": total})
}

func decodePreKeys(w http.ResponseWriter, in []preKeyReq) ([]store.PreKey, bool) {
	out := make([]store.PreKey, 0, len(in))
	for _, k := range in {
		if k.KeyID == "" {
			apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "prekey key_id required", nil)
			return nil, false
		}
		pub, err := base64.StdEncoding.DecodeString(k.Pub)
		if err != nil {
			apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "prekey pub must be base64", nil)
			return nil, false
		}
		sig, err := base64.StdEncoding.DecodeString(k.Signature)
		if err != nil {
			apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "prekey signature must be base64", nil)
			return nil, false
		}
		out = append(out, store.PreKey{KeyID: k.KeyID, Pub: pub, Signature: sig})
	}
	return out, true
}

func encodePreKeys(in []store.PreKey) []map[string]string {
	out := make([]map[string]string, 0, len(in))
	for _, k := range in {
		out = append(out, map[string]string{
			"key_id": k.KeyID, "pub": b64(k.Pub), "signature": b64(k.Signature),
		})
	}
	return out
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// clientIP：限流分桶键（真实客户端 IP）。
// 部署在 Nginx/Caddy + Cloudflare 后，直连对端是反代，必须取可信代理头，
// 否则所有来源共享反代 IP（127.0.0.1 / 容器 IP）会被误杀。
// 优先 CF-Connecting-IP（Cloudflare 边缘写入，客户端无法伪造），
// 回退 X-Forwarded-For 首段（原始客户端），最后才用直连 IP。
func clientIP(r *http.Request) string {
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		return ip
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.IndexByte(xff, ','); idx >= 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
