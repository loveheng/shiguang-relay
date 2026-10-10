package httpapi_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"shiguang-relay/internal/auth"
	"shiguang-relay/internal/httpapi"
	"shiguang-relay/internal/store"
)

// PG 集成测试：自账户端点回环（recovery_vault 读回 = 换机恢复链路闭合验证）。

// TestSelfEndpointsRoundTrip：注册 → SQL 预埋金库 → GET me 读回 → PATCH 更新资料/推送令牌 → 读回验证。
func TestSelfEndpointsRoundTrip(t *testing.T) {
	deps, pool := pgDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	in := registerUser(t, srv, store.MinInitialPreKeys)
	token := login(t, srv, in.username, in.password)

	// 预埋 recovery_vault（注册写路径已有用例；此处专验读回）
	vault := randomBytes(96)
	if _, err := pool.Exec(context.Background(),
		`UPDATE users SET recovery_vault = $2 WHERE user_id = $1`, in.userID, vault); err != nil {
		t.Fatal(err)
	}

	// GET /v1/users/me：身份 + 金库读回
	resp := doJSON(t, srv, http.MethodGet, "/v1/users/me", "", randomID("m"), token)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET me 期望 200，实际 %d: %s", resp.StatusCode, readAll(t, resp))
	}
	var self struct {
		UserID           string `json:"user_id"`
		Username         string `json:"username"`
		EncryptedProfile string `json:"encrypted_profile"`
		RecoveryVault    string `json:"recovery_vault"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&self); err != nil {
		t.Fatal(err)
	}
	if self.UserID != in.userID || self.Username != in.username {
		t.Fatalf("身份不一致: got %s/%s want %s/%s", self.UserID, self.Username, in.userID, in.username)
	}
	if self.RecoveryVault != base64.StdEncoding.EncodeToString(vault) {
		t.Fatal("recovery_vault 读回与预埋不一致（换机恢复链路仍断）")
	}
	if self.EncryptedProfile != "" {
		t.Fatal("未设置过的 encrypted_profile 应缺省（而非空串/base64(空)）")
	}

	// PATCH encrypted_profile → 读回一致
	profile := base64.StdEncoding.EncodeToString(randomBytes(64))
	resp2 := doJSON(t, srv, http.MethodPatch, "/v1/users/me",
		fmt.Sprintf(`{"encrypted_profile":%q}`, profile), randomID("m"), token)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("PATCH profile 期望 200，实际 %d", resp2.StatusCode)
	}

	// PATCH push_token → DB 断言；再 PATCH 空串 → 清空为 NULL
	tok := "fcm-token-abc"
	resp3 := doJSON(t, srv, http.MethodPatch, "/v1/users/me",
		fmt.Sprintf(`{"push_token":%q}`, tok), randomID("m"), token)
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("PATCH push_token 期望 200，实际 %d", resp3.StatusCode)
	}
	assertPushToken(t, pool, in.userID, &tok)

	resp4 := doJSON(t, srv, http.MethodPatch, "/v1/users/me",
		`{"push_token":""}`, randomID("m"), token)
	resp4.Body.Close()
	if resp4.StatusCode != http.StatusOK {
		t.Fatalf("清空 push_token 期望 200，实际 %d", resp4.StatusCode)
	}
	assertPushToken(t, pool, in.userID, nil)

	// GET me：profile 已回读、金库仍在
	resp5 := doJSON(t, srv, http.MethodGet, "/v1/users/me", "", randomID("m"), token)
	defer resp5.Body.Close()
	var self2 struct {
		EncryptedProfile string `json:"encrypted_profile"`
		RecoveryVault    string `json:"recovery_vault"`
	}
	if err := json.NewDecoder(resp5.Body).Decode(&self2); err != nil {
		t.Fatal(err)
	}
	if self2.EncryptedProfile != profile {
		t.Fatal("encrypted_profile 读回与 PATCH 不一致")
	}
	if self2.RecoveryVault != base64.StdEncoding.EncodeToString(vault) {
		t.Fatal("PATCH 资料不应动 recovery_vault")
	}

	// PATCH recovery_vault（金库轮换）→ 读回一致，且不影响 profile
	vault2 := base64.StdEncoding.EncodeToString(randomBytes(96))
	resp6 := doJSON(t, srv, http.MethodPatch, "/v1/users/me",
		fmt.Sprintf(`{"recovery_vault":%q}`, vault2), randomID("m"), token)
	resp6.Body.Close()
	if resp6.StatusCode != http.StatusOK {
		t.Fatalf("PATCH vault 期望 200，实际 %d", resp6.StatusCode)
	}
	resp7 := doJSON(t, srv, http.MethodGet, "/v1/users/me", "", randomID("m"), token)
	defer resp7.Body.Close()
	var self3 struct {
		EncryptedProfile string `json:"encrypted_profile"`
		RecoveryVault    string `json:"recovery_vault"`
	}
	if err := json.NewDecoder(resp7.Body).Decode(&self3); err != nil {
		t.Fatal(err)
	}
	if self3.RecoveryVault != vault2 {
		t.Fatal("recovery_vault 读回与 PATCH 不一致（金库轮换链路仍断）")
	}
	if self3.EncryptedProfile != profile {
		t.Fatal("PATCH vault 不应动 encrypted_profile")
	}
}

// TestGetMeRejectsUnknownCaller：Bearer 签名合法但指向不存在的用户 → 401（不泄露存在性细节）。
func TestGetMeRejectsUnknownCaller(t *testing.T) {
	deps, _ := pgDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	// 用与 pgDeps 相同密钥自签一个指向不存在用户的合法 Bearer
	ghost := auth.NewIssuer([]byte("test-secret-test-secret-test-secret"), time.Hour, 24*time.Hour)
	pair, err := ghost.Issue(context.Background(), randomID("ghost"))
	if err != nil {
		t.Fatal(err)
	}

	resp := doJSON(t, srv, http.MethodGet, "/v1/users/me", "", randomID("m"), pair.AccessToken)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("幽灵用户期望 401，实际 %d", resp.StatusCode)
	}
}

func assertPushToken(t *testing.T, pool *pgxpool.Pool, userID string, want *string) {
	t.Helper()
	var got *string
	if err := pool.QueryRow(context.Background(),
		`SELECT push_token FROM users WHERE user_id = $1`, userID).Scan(&got); err != nil {
		t.Fatal(err)
	}
	switch {
	case want == nil && got != nil:
		t.Fatalf("push_token 期望 NULL，实际 %q", *got)
	case want != nil && (got == nil || *got != *want):
		t.Fatalf("push_token 期望 %q，实际 %v", *want, got)
	}
}
