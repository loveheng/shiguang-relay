package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"shiguang-relay/internal/apierr"
	"shiguang-relay/internal/auth"
	"shiguang-relay/internal/httpapi"
)

// Token 撤销机制测试（无需 PG）：rotation 重用检测 / 登出撤销。改密踢会话见 *_pg_test。

// issuePair：直接经 Issuer 签一对（绕过登录，聚焦撤销语义本身）。
func issuePair(t *testing.T, deps httpapi.Deps) (access, refresh string) {
	t.Helper()
	pair, err := deps.Issuer.Issue(t.Context(), "user-1")
	if err != nil {
		t.Fatal(err)
	}
	return pair.AccessToken, pair.RefreshToken
}

// TestRefreshRotationDetectsReuse：换新后旧 refresh 重用 → 401 TOKEN_REVOKED；新对不受影响。
func TestRefreshRotationDetectsReuse(t *testing.T) {
	deps := newDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()
	_, refresh := issuePair(t, deps)

	// 第一次换新 → 200 新对
	resp := doJSON(t, srv, http.MethodPost, "/v1/auth/refresh",
		`{"refresh_token":"`+refresh+`"}`, randomID("m"), "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("首次换新期望 200，实际 %d", resp.StatusCode)
	}

	// 旧 refresh 重用 → 401 TOKEN_REVOKED（rotation 已拉黑 jti）
	resp2 := doJSON(t, srv, http.MethodPost, "/v1/auth/refresh",
		`{"refresh_token":"`+refresh+`"}`, randomID("m"), "")
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("重用旧 refresh 期望 401，实际 %d", resp2.StatusCode)
	}
	if code := errorCode(t, resp2); code != apierr.TokenRevoked {
		t.Fatalf("错误码期望 TOKEN_REVOKED，实际 %s", code)
	}
}

// TestLogoutRevokesBothTokens：登出后 access 打业务路由 401；refresh 换新 401。
func TestLogoutRevokesBothTokens(t *testing.T) {
	deps := newDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()
	access, refresh := issuePair(t, deps)

	// 登出（带 refresh_token 一并撤销）
	resp := doJSON(t, srv, http.MethodPost, "/v1/auth/logout",
		`{"refresh_token":"`+refresh+`"}`, randomID("m"), access)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("登出期望 200，实际 %d", resp.StatusCode)
	}

	// 旧 access 打受保护路由 → 401（jti 黑名单）
	resp2 := doJSON(t, srv, http.MethodGet, "/v1/users/me", "", randomID("m"), access)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("登出后旧 access 期望 401，实际 %d", resp2.StatusCode)
	}

	// 旧 refresh 换新 → 401
	resp3 := doJSON(t, srv, http.MethodPost, "/v1/auth/refresh",
		`{"refresh_token":"`+refresh+`"}`, randomID("m"), "")
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusUnauthorized {
		t.Fatalf("登出后旧 refresh 期望 401，实际 %d", resp3.StatusCode)
	}
}

// TestDenyListExpires：黑名单随 token 剩余寿命自然出池（miniredis 快进验证）。
func TestDenyListExpires(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	dl := auth.NewDenyList(rdb)

	ctx := t.Context()
	if err := dl.Add(ctx, "jti-x", time.Minute); err != nil {
		t.Fatal(err)
	}
	if !dl.Has(ctx, "jti-x") {
		t.Fatal("拉黑后应命中")
	}
	mr.FastForward(2 * time.Minute)
	if dl.Has(ctx, "jti-x") {
		t.Fatal("TTL 过期后应出池")
	}
	if dl.Has(ctx, "") {
		t.Fatal("空 jti 恒不命中")
	}
}
