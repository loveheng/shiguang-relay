package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"shiguang-relay/internal/httpapi"
)

// TestSelfEndpointsAuthGate：自账户端点的鉴权与空更新校验（无需 PG，走到 store 之前即返回）。
func TestSelfEndpointsAuthGate(t *testing.T) {
	deps := newDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	// GET /v1/users/me 无 token → 401
	resp := doJSON(t, srv, http.MethodGet, "/v1/users/me", "", randomID("m"), "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET me 未鉴权期望 401，实际 %d", resp.StatusCode)
	}

	// PATCH /v1/users/me 无 token → 401
	resp = doJSON(t, srv, http.MethodPatch, "/v1/users/me", `{}`, randomID("m"), "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("PATCH me 未鉴权期望 401，实际 %d", resp.StatusCode)
	}

	// PATCH 带 token 但两个更新字段全缺省 → 400（nothing to update，不触 store）
	token := login(t, srv, "user-1", "pass")
	resp = doJSON(t, srv, http.MethodPatch, "/v1/users/me", `{}`, randomID("m"), token)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("空更新期望 400，实际 %d", resp.StatusCode)
	}
}
