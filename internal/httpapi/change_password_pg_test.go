package httpapi_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"shiguang-relay/internal/apierr"
	"shiguang-relay/internal/httpapi"
	"shiguang-relay/internal/store"
)

// 改密踢会话（需 RELAY_TEST_PG_DSN）：改密后旧 access/refresh 即时失效，新密码可重登。

func TestChangePasswordKicksSessions(t *testing.T) {
	deps, _ := pgDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	in := registerUser(t, srv, store.MinInitialPreKeys)
	access := login(t, srv, in.username, in.password)

	// 改密前签一对 refresh（纪元 0）
	pair, err := deps.Issuer.Issue(context.Background(), in.userID)
	if err != nil {
		t.Fatal(err)
	}

	newPw := "NewPw_12345678"
	resp := doJSON(t, srv, http.MethodPost, "/v1/auth/change-password",
		fmt.Sprintf(`{"old_password":%q,"new_password":%q}`, in.password, newPw), randomID("m"), access)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("改密期望 200，实际 %d", resp.StatusCode)
	}

	// 旧 access → 401 TOKEN_STALE（纪元落后）
	resp2 := doJSON(t, srv, http.MethodGet, "/v1/users/me", "", randomID("m"), access)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("改密后旧 access 期望 401，实际 %d", resp2.StatusCode)
	}
	if code := errorCode(t, resp2); code != apierr.TokenStale {
		t.Fatalf("错误码期望 TOKEN_STALE，实际 %s", code)
	}

	// 旧 refresh 换新 → 401 TOKEN_STALE
	resp3 := doJSON(t, srv, http.MethodPost, "/v1/auth/refresh",
		`{"refresh_token":"`+pair.RefreshToken+`"}`, randomID("m"), "")
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusUnauthorized {
		t.Fatalf("改密后旧 refresh 期望 401，实际 %d", resp3.StatusCode)
	}
	if code := errorCode(t, resp3); code != apierr.TokenStale {
		t.Fatalf("refresh 错误码期望 TOKEN_STALE，实际 %s", code)
	}

	// 新密码重登 → 新 access 可正常访问
	token := login(t, srv, in.username, newPw)
	resp4 := doJSON(t, srv, http.MethodGet, "/v1/users/me", "", randomID("m"), token)
	defer resp4.Body.Close()
	if resp4.StatusCode != http.StatusOK {
		t.Fatalf("新会话期望 200，实际 %d", resp4.StatusCode)
	}
}
