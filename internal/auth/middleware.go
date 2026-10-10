package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"shiguang-relay/internal/apierr"
)

type ctxKeyUser struct{}
type ctxKeyClaims struct{}

// UserIDFromContext：取出中间件写入的 user_id（未走鉴权的路由返回空串）。
func UserIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyUser{}).(string)
	return v
}

// ClaimsFromContext：取出中间件写入的完整载荷（登出撤销 jti 用；未走鉴权返回零值）。
func ClaimsFromContext(ctx context.Context) Claims {
	c, _ := ctx.Value(ctxKeyClaims{}).(Claims)
	return c
}

// RequireAuth：Bearer access_token 校验（签名无状态 + 纪元有状态）。
// 纪元比对（ver < 当前 → TOKEN_STALE）使改密后所有旧会话即时失效；
// 纪元存储故障 fail-open（与全库限流口径一致）。
// 失败一律 401 —— 已验签通过后才有资格区分 STALE（不给未验签流量任何反馈面）。
func RequireAuth(iss *Issuer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") {
				apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized,
					"missing bearer access token", nil)
				return
			}
			claims, err := iss.VerifyClaims(strings.TrimPrefix(header, "Bearer "), "access")
			if err != nil {
				apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized,
					"invalid or expired access token", nil)
				return
			}
			if iss.Revoked(r.Context(), claims.JTI) {
				apierr.Write(w, http.StatusUnauthorized, apierr.TokenRevoked,
					"token revoked", nil)
				return
			}
			if !iss.CheckEpoch(r.Context(), claims.UserID, claims.Ver) {
				apierr.Write(w, http.StatusUnauthorized, apierr.TokenStale,
					"session invalidated, please log in again", nil)
				return
			}
			ctx := context.WithValue(r.Context(), ctxKeyUser{}, claims.UserID)
			next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, ctxKeyClaims{}, claims)))
		})
	}
}

// ErrNotImplemented：占位路由返回，供 Phase 1.4 收口前联调靶场使用。
var ErrNotImplemented = errors.New("not implemented in current phase")
