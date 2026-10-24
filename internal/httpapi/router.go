// Package httpapi：REST 路由与处理器装配。
// Phase 1.1 只落鉴权闭环（Challenge-Response + 双 Token + 幂等去重）；
// POST /v1/schedule/action 目前为 501 占位，Phase 1.4 收口。
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
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

	// 账号体系（Plan A：用户名+密码仅鉴权，与 E2EE 密钥解耦）
	Credentials CredentialVerifier // 用户名+密码校验（生产=store.UserStore；测试可注入假实现）

	// 登录防爆破双桶（nil 容忍——单测可不注入，nil 时跳过对应防线）：
	//   LoginLimiter：IP 桶，计数所有登录请求（挡扫射）；
	//   LoginGuard：账号桶，仅计失败（挡定点爆破），成功清零。
	LoginLimiter    *auth.RateLimiter
	LoginGuard      *auth.LoginGuard
	LoginLockWindow time.Duration

	// Token 撤销（nil 容忍）：
	//   Deny：jti 黑名单（refresh rotation 重用检测 / 登出）；
	//   Epochs：用户令牌纪元（改密全量踢旧会话；Issuer 需 SetEpoch 后 ver 才非 0）。
	Deny   *auth.DenyList
	Epochs *auth.EpochStore

	// Phase 1.3：好友域（Ticket 制建联）
	Friends                 store.FriendsStore
	FriendInviteLimitPerMin int

	// Phase 1.4：协同动作（行锁取号 + 单事务落库）
	Bundles     store.BundlesStore
	Broadcaster Broadcaster // Phase 1.6 换成 WSS Hub

	// v0.1.8：瞬时信令在线直推（nil 容忍——不注入则纯 REST 拉取）
	RelayPusher RelayPusher

	// Phase 1.6：WSS（nil 时不挂载 /ws，便于单测只跑 REST）
	WSS http.Handler

	// Phase 1.8：健康检查探针（nil 则跳过该项）
	HealthPG    func(ctx context.Context) error
	HealthRedis func(ctx context.Context) error
}

// CredentialVerifier：用户名+密码校验（Plan A：密码仅鉴权，与 E2EE 密钥解耦）。
// 生产实现走 store.UserStore.VerifyPassword（按 username 取哈希判定）；测试可注入假实现，无需真 PG。
type CredentialVerifier interface {
	VerifyPassword(ctx context.Context, username, password string) (userID string, ok bool, err error)
}

func NewRouter(d Deps) http.Handler {
	mux := http.NewServeMux()
	// WSS：纯路径建连（token 绝不进 URL），首帧 AUTH 3s 掐线；未注入则不挂载（单测只跑 REST）
	if d.WSS != nil {
		mux.Handle("GET /ws", d.WSS)
	}

	mux.HandleFunc("GET /v1/healthz", func(w http.ResponseWriter, r *http.Request) {
		// 真探针：PG/Redis 任一不可达即 503（探针不给外网探，见 deploy/Caddyfile）
		checks := map[string]any{}
		ok := true
		if d.HealthPG != nil {
			if err := d.HealthPG(r.Context()); err != nil {
				ok = false
				checks["pg"] = "down"
			} else {
				checks["pg"] = "up"
			}
		}
		if d.HealthRedis != nil {
			if err := d.HealthRedis(r.Context()); err != nil {
				ok = false
				checks["redis"] = "down"
			} else {
				checks["redis"] = "up"
			}
		}
		status := http.StatusOK
		if !ok {
			status = http.StatusServiceUnavailable
		}
		apierr.WriteJSON(w, status, map[string]any{"ok": ok, "ts": time.Now().Unix(), "checks": checks})
	})

	mux.Handle("POST /v1/auth/challenge", d.Idem.Wrap(http.HandlerFunc(d.handleChallenge)))
	mux.Handle("POST /v1/auth/login", d.Idem.Wrap(http.HandlerFunc(d.handleLogin)))
	mux.Handle("POST /v1/auth/refresh", d.Idem.Wrap(http.HandlerFunc(d.handleRefresh)))
	mux.Handle("POST /v1/auth/logout",
		auth.RequireAuth(d.Issuer)(d.Idem.Wrap(http.HandlerFunc(d.handleLogout))))
	mux.Handle("POST /v1/auth/change-password",
		auth.RequireAuth(d.Issuer)(d.Idem.Wrap(http.HandlerFunc(d.handleChangePassword))))

	// Phase 1.2：注册（PoP 自签 + PoW + IP 限流）与 PreKey 托管
	mux.Handle("POST /v1/users", d.Idem.Wrap(http.HandlerFunc(d.handleRegister)))
	mux.Handle("GET /v1/users/{user_id}/prekey", d.Idem.Wrap(http.HandlerFunc(d.handleGetPreKey)))
	mux.Handle("GET /v1/users/lookup",
		auth.RequireAuth(d.Issuer)(d.Idem.Wrap(http.HandlerFunc(d.handleLookupUser))))
	// 自账户：读回自身份（含 recovery_vault——换机恢复链路）与密文资料/推送令牌更新
	mux.Handle("GET /v1/users/me",
		auth.RequireAuth(d.Issuer)(d.Idem.Wrap(http.HandlerFunc(d.handleGetMe))))
	mux.Handle("PATCH /v1/users/me",
		auth.RequireAuth(d.Issuer)(d.Idem.Wrap(http.HandlerFunc(d.handleUpdateMe))))
	mux.Handle("POST /v1/users/me/prekeys",
		auth.RequireAuth(d.Issuer)(d.Idem.Wrap(http.HandlerFunc(d.handleRefillPreKeys))))

	// Phase 1.3：好友建联（全部要求 Bearer）——扫码 Ticket 与用户名搜索双通道
	mux.Handle("POST /v1/friends/invite",
		auth.RequireAuth(d.Issuer)(d.Idem.Wrap(http.HandlerFunc(d.handleInviteFriend))))
	mux.Handle("POST /v1/friends/request",
		auth.RequireAuth(d.Issuer)(d.Idem.Wrap(http.HandlerFunc(d.handleFriendRequest))))
	mux.Handle("POST /v1/friends/accept",
		auth.RequireAuth(d.Issuer)(d.Idem.Wrap(http.HandlerFunc(d.handleAcceptFriend))))
	mux.Handle("GET /v1/friends",
		auth.RequireAuth(d.Issuer)(d.Idem.Wrap(http.HandlerFunc(d.handleListFriends))))
	mux.Handle("DELETE /v1/friends/{user_id}",
		auth.RequireAuth(d.Issuer)(d.Idem.Wrap(http.HandlerFunc(d.handleRemoveFriend))))
	mux.Handle("POST /v1/friends/{user_id}/block",
		auth.RequireAuth(d.Issuer)(d.Idem.Wrap(http.HandlerFunc(d.handleBlockFriend))))

	// Phase 1.5：发现与同步（换机冷启动链路）+ 密钥信封 + 瞬时信令
	mux.Handle("GET /v1/bundles/participating",
		auth.RequireAuth(d.Issuer)(d.Idem.Wrap(http.HandlerFunc(d.handleListParticipating))))
	mux.Handle("GET /v1/schedule/sync",
		auth.RequireAuth(d.Issuer)(d.Idem.Wrap(http.HandlerFunc(d.handleSync))))
	mux.Handle("GET /v1/bundles/{bundle_id}/key-envelopes",
		auth.RequireAuth(d.Issuer)(d.Idem.Wrap(http.HandlerFunc(d.handleKeyEnvelopes))))
	mux.Handle("POST /v1/vault/envelopes",
		auth.RequireAuth(d.Issuer)(d.Idem.Wrap(http.HandlerFunc(d.handleVaultAppend))))
	mux.Handle("GET /v1/vault/envelopes",
		auth.RequireAuth(d.Issuer)(d.Idem.Wrap(http.HandlerFunc(d.handleVaultList))))
	mux.Handle("POST /v1/relay/msg",
		auth.RequireAuth(d.Issuer)(d.Idem.Wrap(http.HandlerFunc(d.handleRelaySend))))
	mux.Handle("GET /v1/relay/pending",
		auth.RequireAuth(d.Issuer)(d.Idem.Wrap(http.HandlerFunc(d.handleRelayPending))))
	mux.Handle("POST /v1/relay/ack",
		auth.RequireAuth(d.Issuer)(d.Idem.Wrap(http.HandlerFunc(d.handleRelayAck))))

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
	Username string `json:"username"`
	Password string `json:"password"`
}

type refreshReq struct {
	RefreshToken string `json:"refresh_token"`
}

// logoutReq：登出请求体；refresh_token 可选（带上则一并撤销）。
type logoutReq struct {
	RefreshToken string `json:"refresh_token"`
}

type changePasswordReq struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
	// NewRecoveryVault：新密码派生 KEK 重封的金库密文（base64，端侧改密原子重封，v3 拍板）。
	// 与密码哈希同事务落库；缺省=不改金库（兼容无金库账号）。
	NewRecoveryVault []byte `json:"new_recovery_vault"`
}

func (d Deps) handleChallenge(w http.ResponseWriter, r *http.Request) {
	var req challengeReq
	if !decode(w, r, &req) {
		return
	}
	// user_id 可选：注册阶段尚无 user_id（用户名体系下注册不带 user_id），登录阶段也已无需 challenge 绑定。
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
	if req.Username == "" || req.Password == "" {
		apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "username and password required", nil)
		return
	}
	// 用户名归一小写（与注册一致）。
	username := strings.ToLower(strings.TrimSpace(req.Username))

	// 防爆破双桶（与注册 Sybil 防线同哲学）：
	//   IP 桶——计数所有请求（含成功），挡分布式扫射；
	//   账号桶（LoginGuard）——仅计失败，挡定点爆破。
	// Redis 抖动一律放行（限流不是最后一道防线，与 register 口径一致）。
	if d.LoginLimiter != nil {
		allowed, _, err := d.LoginLimiter.Allow(r.Context(), "login", clientIP(r))
		if err != nil {
			allowed = true
		}
		if !allowed {
			apierr.Write(w, http.StatusTooManyRequests, apierr.LoginThrottled,
				"too many login attempts", nil)
			return
		}
	}
	if d.LoginGuard != nil {
		blocked, err := d.LoginGuard.Blocked(r.Context(), username)
		if err != nil {
			blocked = false
		}
		if blocked {
			apierr.Write(w, http.StatusTooManyRequests, apierr.LoginThrottled,
				"account temporarily locked after too many failed logins",
				map[string]any{"retry_after_sec": int(d.LoginLockWindow.Seconds())})
			return
		}
	}

	// 按 username 校验密码哈希（Plan A：密码仅鉴权）。
	// 用户不存在与密码错误同一响应口径，避免账号枚举侧信道。
	userID, ok, err := d.Credentials.VerifyPassword(r.Context(), username, req.Password)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "credential check failure", nil)
		return
	}
	if !ok {
		// 失败记账不阻断 401 主口径（记账失败时下次窗口自然重置）
		if d.LoginGuard != nil {
			_ = d.LoginGuard.RecordFail(r.Context(), username)
		}
		apierr.Write(w, http.StatusUnauthorized, apierr.UserOrPasswordInvalid, "invalid username or password", nil)
		return
	}
	if d.LoginGuard != nil {
		d.LoginGuard.Reset(r.Context(), username)
	}
	pair, err := d.Issuer.Issue(r.Context(), userID)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to issue tokens", nil)
		return
	}
	apierr.WriteJSON(w, http.StatusOK, pair)
}

// handleChangePassword：POST /v1/auth/change-password —— 改密（Plan A：仅换密码哈希，不动 E2EE 密钥）。
func (d Deps) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserIDFromContext(r.Context())
	if caller == "" {
		apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized, "missing bearer access token", nil)
		return
	}
	var req changePasswordReq
	if !decode(w, r, &req) {
		return
	}
	if len(req.NewPassword) < minPasswordLen {
		apierr.Write(w, http.StatusBadRequest, apierr.PasswordTooWeak,
			"password too weak", map[string]any{"min_len": minPasswordLen})
		return
	}
	// 先校验旧密码（按 user_id，不改依赖 username）
	ok, err := d.Users.CheckPasswordByUserID(r.Context(), caller, req.OldPassword)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "password check failure", nil)
		return
	}
	if !ok {
		apierr.Write(w, http.StatusUnauthorized, apierr.PasswordMismatch, "old password incorrect", nil)
		return
	}
	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to hash password", nil)
		return
	}
	// v3 拍板：改密=原子重封——旧密文验证通过后，新哈希与新金库密文单事务同落；
	// 缺省 new_recovery_vault 时不改金库（纯改密兼容）。
	if err := d.Users.UpdatePasswordWithVault(r.Context(), caller, newHash, req.NewRecoveryVault); err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to update password", nil)
		return
	}
	// 改密踢会话：令牌纪元 +1，该用户全部既有 access/refresh 即时失效（被盗 token 止损）
	if d.Epochs != nil {
		_ = d.Epochs.Bump(r.Context(), caller)
	}
	apierr.WriteJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (d Deps) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req refreshReq
	if !decode(w, r, &req) {
		return
	}
	claims, err := d.Issuer.VerifyClaims(req.RefreshToken, "refresh")
	if err != nil {
		apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized, "invalid or expired refresh token", nil)
		return
	}
	// 重用检测：rotation 已换新过的 refresh（jti 在黑名单）→ 拒绝（盗号止损）
	if d.Deny != nil && d.Deny.Has(r.Context(), claims.JTI) {
		apierr.Write(w, http.StatusUnauthorized, apierr.TokenRevoked, "refresh token revoked", nil)
		return
	}
	// 改密后旧 refresh 一并失效（纪元比对，与中间件同口径）
	if !d.Issuer.CheckEpoch(r.Context(), claims.UserID, claims.Ver) {
		apierr.Write(w, http.StatusUnauthorized, apierr.TokenStale, "session invalidated, please log in again", nil)
		return
	}
	pair, err := d.Issuer.Issue(r.Context(), claims.UserID)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to issue tokens", nil)
		return
	}
	// rotation：旧 refresh jti 拉黑至原到期时刻——已签发新对，旧实例自此只能被识别为重放
	if d.Deny != nil && claims.JTI != "" {
		if ttl := time.Until(time.Unix(claims.Expiry, 0)); ttl > 0 {
			_ = d.Deny.Add(r.Context(), claims.JTI, ttl)
		}
	}
	apierr.WriteJSON(w, http.StatusOK, pair)
}

// handleLogout：POST /v1/auth/logout —— 主动登出（access + refresh 双 jti 拉黑至各自到期）。
// 幂等：重复登出同一 token 重复拉黑无害；已过期 token 拉黑是 no-op。
func (d Deps) handleLogout(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims.UserID == "" {
		apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized, "missing bearer access token", nil)
		return
	}
	if d.Deny != nil {
		if ttl := time.Until(time.Unix(claims.Expiry, 0)); ttl > 0 {
			_ = d.Deny.Add(r.Context(), claims.JTI, ttl)
		}
		var req logoutReq
		if decode(w, r, &req) && req.RefreshToken != "" {
			if rc, err := d.Issuer.VerifyClaims(req.RefreshToken, "refresh"); err == nil && rc.JTI != "" {
				if ttl := time.Until(time.Unix(rc.Expiry, 0)); ttl > 0 {
					_ = d.Deny.Add(r.Context(), rc.JTI, ttl)
				}
			}
			// 非法/过期 refresh 静默忽略——登出永远成功，不泄露 token 状态
		}
	}
	apierr.WriteJSON(w, http.StatusOK, map[string]any{"status": "ok"})
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
