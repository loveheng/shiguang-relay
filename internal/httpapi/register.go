package httpapi

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"net/http"

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
	UserID           string      `json:"user_id"`
	IdentityKeyPub   string      `json:"identity_key_pub"`
	SignedPrekeyPub  string      `json:"signed_prekey_pub"`
	SignedPrekeySig  string      `json:"signed_prekey_sig"`
	PushToken        string      `json:"push_token"`
	EncryptedProfile string      `json:"encrypted_profile"`
	RecoveryVault    string      `json:"recovery_vault"`
	Nonce            string      `json:"nonce"`
	SignedPop        string      `json:"signed_pop"`
	PowSolution      string      `json:"pow_solution"`
	OneTimePreKeys   []preKeyReq `json:"one_time_prekeys"`
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

	// 1) nonce：一次性消费（Challenge-Response）
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

	// 2) PoW
	if d.PoWRequired && !auth.VerifyPoW(pow, req.PowSolution, d.Challenges.Difficulty()) {
		apierr.Write(w, http.StatusUnauthorized, apierr.PowSolutionInvalid, "proof of work solution invalid", nil)
		return
	}

	// 3) PoP 自签：公钥取自请求体，验签通过即证明请求方持有对应私钥
	identityPub, err := base64.StdEncoding.DecodeString(req.IdentityKeyPub)
	if err != nil {
		apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "identity_key_pub must be base64", nil)
		return
	}
	sig, err := base64.StdEncoding.DecodeString(req.SignedPop)
	if err != nil {
		apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "signed_pop must be base64", nil)
		return
	}
	if !auth.VerifyPoP(identityPub, sig, req.Nonce) {
		apierr.Write(w, http.StatusUnauthorized, apierr.PopSignatureInvalid, "proof of possession signature invalid", nil)
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

	// 4) OPK 瘦身：首批只允许 10~20
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

	// 5) 单事务落用户 + 首批 OPK
	err = d.Users.CreateUserWithPreKeys(r.Context(), store.CreateUserInput{
		UserID:           req.UserID,
		IdentityKeyPub:   identityPub,
		SignedPrekeyPub:  spkPub,
		SignedPrekeySig:  spkSig,
		PushToken:        req.PushToken,
		EncryptedProfile: profile,
		RecoveryVault:    vault,
	}, keys)
	if errors.Is(err, store.ErrUserExists) {
		apierr.Write(w, http.StatusConflict, apierr.UserAlreadyExists, "user already registered", nil)
		return
	}
	if err != nil {
		// 细节只进服务端日志：错误通道零明文红线（§10.4）
		slog.Error("创建用户失败", "err", err, "user_id", req.UserID)
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to create user", nil)
		return
	}

	apierr.WriteJSON(w, http.StatusCreated, map[string]any{
		"user_id":   req.UserID,
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

// clientIP：取对端 IP（限流分桶键）。
// 部署在 Caddy/Nginx 后请改用 X-Forwarded-For 首段——否则所有来源共享反代 IP 会被误杀，
// 这里保持最简实现并在 README 部署章节标注。
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
