package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"shiguang-relay/internal/apierr"
)

type ctxKeyUser struct{}

// UserIDFromContext：取出中间件写入的 user_id（未走鉴权的路由返回空串）。
func UserIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyUser{}).(string)
	return v
}

// RequireAuth：Bearer access_token 校验（无状态）。
// 失败一律 401 UNAUTHORIZED —— 不区分「没带 / 过期 / 被篡改」，避免给攻击者反馈面。
func RequireAuth(iss *Issuer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") {
				apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized,
					"missing bearer access token", nil)
				return
			}
			userID, err := iss.Verify(strings.TrimPrefix(header, "Bearer "), "access")
			if err != nil {
				apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized,
					"invalid or expired access token", nil)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyUser{}, userID)))
		})
	}
}

// ErrNotImplemented：占位路由返回，供 Phase 1.4 收口前联调靶场使用。
var ErrNotImplemented = errors.New("not implemented in current phase")
