package httpapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"shiguang-relay/internal/auth"
	"shiguang-relay/internal/httpapi"
)

// fakeIdentities：IdentityResolver 假实现（Ticket 域用；本文件测试路径不触发）。
type fakeIdentities struct{}

func (fakeIdentities) IdentityKey(_ context.Context, _ string) ([]byte, error) {
	return []byte("fake-pub"), nil
}

// fakeCreds：用户名+密码校验假实现（Plan A 登录无需真 PG）。
type fakeCreds struct{ userID string }

func (f fakeCreds) VerifyPassword(_ context.Context, username, password string) (string, bool, error) {
	if username == "user-1" && password == "pass" {
		return f.userID, true, nil
	}
	return "", false, nil
}

func newDeps(t *testing.T) httpapi.Deps {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	issuer := auth.NewIssuer([]byte("test-secret-test-secret-test-secret"), time.Hour, 24*time.Hour)
	epochs := auth.NewEpochStore(rdb, 24*time.Hour)
	deny := auth.NewDenyList(rdb)
	issuer.SetEpoch(epochs)
	issuer.SetDeny(deny)
	return httpapi.Deps{
		Issuer:              issuer,
		Challenges:          auth.NewChallengeStore(rdb, time.Minute, 2),
		Idem:                auth.NewIdempotency(rdb, 5*time.Minute, 5*time.Minute),
		Identities:          fakeIdentities{},
		Credentials:         fakeCreds{userID: "user-1"},
		Limiter:             auth.NewRateLimiter(rdb, 100, time.Minute),
		RegisterLimitPerMin: 100,
		PoWRequired:         true,
		Deny:                deny,
		Epochs:              epochs,
	}
}

func doJSON(t *testing.T, srv *httptest.Server, method, path, body, msgID, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if msgID != "" {
		req.Header.Set(auth.HeaderClientMsgID, msgID)
		req.Header.Set(auth.HeaderClientTs, fmt.Sprintf("%d", time.Now().Unix()))
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// login：用户名+密码登录（Plan A）拿 access_token。
// msg_id 必须每次唯一——幂等中间件会把同 key 的第二次请求回放成首次响应。
func login(t *testing.T, srv *httptest.Server, username, password string) string {
	t.Helper()
	resp := doJSON(t, srv, http.MethodPost, "/v1/auth/login",
		fmt.Sprintf(`{"username":%q,"password":%q}`, username, password), randomID("m"), "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login 期望 200，实际 %d: %s", resp.StatusCode, readAll(t, resp))
	}
	var pair auth.TokenPair
	if err := json.NewDecoder(resp.Body).Decode(&pair); err != nil {
		t.Fatal(err)
	}
	if pair.AccessToken == "" {
		t.Fatal("未返回 access_token")
	}
	return pair.AccessToken
}

func TestScheduleActionRequiresToken(t *testing.T) {
	deps := newDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	// 无 token → 401
	resp := doJSON(t, srv, http.MethodPost, "/v1/schedule/action", `{}`, "msg-1", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("无 token 期望 401，实际 %d", resp.StatusCode)
	}

	// 带合法 token → 进入真实业务校验（Phase 1.4 已收口）：空体缺 cipher → 400
	token := login(t, srv, "user-1", "pass")
	resp2 := doJSON(t, srv, http.MethodPost, "/v1/schedule/action", `{}`, "msg-2", token)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("带 token 但缺 cipher 期望 400，实际 %d", resp2.StatusCode)
	}
}

func TestReplayIsIdempotent(t *testing.T) {
	deps := newDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()
	token := login(t, srv, "user-1", "pass")

	first := doJSON(t, srv, http.MethodPost, "/v1/schedule/action", `{}`, "msg-replay", token)
	body1 := readAll(t, first)
	first.Body.Close()

	second := doJSON(t, srv, http.MethodPost, "/v1/schedule/action", `{}`, "msg-replay", token)
	body2 := readAll(t, second)
	second.Body.Close()

	if second.Header.Get(auth.HeaderReplay) != "1" {
		t.Fatal("重放响应应带 X-Idempotent-Replay: 1")
	}
	if body1 != body2 {
		t.Fatalf("重放响应体应与首次一致:\n%s\n%s", body1, body2)
	}
	if second.StatusCode != first.StatusCode {
		t.Fatalf("重放状态码应一致: %d vs %d", first.StatusCode, second.StatusCode)
	}
}

func TestMissingClientMsgIDRejected(t *testing.T) {
	deps := newDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	resp := doJSON(t, srv, http.MethodPost, "/v1/auth/challenge", `{}`, "", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("缺 client_msg_id 期望 400，实际 %d", resp.StatusCode)
	}
}

// 幂等去重键作用域（v0.1.10 缺陷修复）：同 client_msg_id 打不同端点不得串缓存；
// 读接口（GET）直通不缓存。键=idem:{method}:{path}:{client_msg_id}。
func TestIdempotencyKeyScopedByMethodAndPath(t *testing.T) {
	deps := newDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()
	token := login(t, srv, "user-1", "pass")

	// 跨端点：challenge 先占 msg-id 缓存，login 同 msg-id 不得回放 challenge 响应
	r1 := doJSON(t, srv, http.MethodPost, "/v1/auth/challenge", `{}`, "scope-id", "")
	r1.Body.Close()
	if r1.StatusCode != http.StatusOK {
		t.Fatalf("challenge 期望 200，实际 %d", r1.StatusCode)
	}
	r2 := doJSON(t, srv, http.MethodPost, "/v1/auth/login",
		`{"username":"user-1","password":"wrong"}`, "scope-id", "")
	defer r2.Body.Close()
	if r2.Header.Get(auth.HeaderReplay) == "1" || r2.StatusCode == r1.StatusCode {
		t.Fatalf("跨端点同 msg-id 串了缓存：login=%d replay=%q", r2.StatusCode, r2.Header.Get(auth.HeaderReplay))
	}

	// 同端点重放仍生效
	r3 := doJSON(t, srv, http.MethodPost, "/v1/auth/challenge", `{}`, "scope-id", "")
	r3.Body.Close()
	if r3.Header.Get(auth.HeaderReplay) != "1" {
		t.Fatal("同端点同 msg-id 应命中去重回放")
	}

	// GET 直通：同 msg-id 两次请求均真实执行（无 replay 头）；这里用 lookup 的
	// 参数校验分支（不触 DB）判定「确实执行了业务」——两次都应回 USERNAME_INVALID 400
	g1 := doJSON(t, srv, http.MethodGet, "/v1/users/lookup?username=x", "", "get-scope-id", token)
	g1.Body.Close()
	g2 := doJSON(t, srv, http.MethodGet, "/v1/users/lookup?username=x", "", "get-scope-id", token)
	defer g2.Body.Close()
	if g1.StatusCode != http.StatusBadRequest || g2.StatusCode != http.StatusBadRequest {
		t.Fatalf("GET 两次应各自执行业务（期望 400/400），实际 %d/%d", g1.StatusCode, g2.StatusCode)
	}
	if g2.Header.Get(auth.HeaderReplay) == "1" {
		t.Fatal("GET 不应走幂等缓存回放")
	}
}

func TestLoginRejectsBadPassword(t *testing.T) {
	deps := newDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	resp := doJSON(t, srv, http.MethodPost, "/v1/auth/login",
		`{"username":"user-1","password":"wrong"}`, "msg-l2", "")
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("错误密码不应签发 Token")
	}
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return sb.String()
}
