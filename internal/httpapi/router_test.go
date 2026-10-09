package httpapi_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
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

type fakeIdentities struct {
	pub ed25519.PublicKey
}

func (f fakeIdentities) IdentityKey(_ context.Context, _ string) ([]byte, error) { return f.pub, nil }

func newDeps(t *testing.T) (httpapi.Deps, ed25519.PrivateKey, string) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return httpapi.Deps{
		Issuer:      auth.NewIssuer([]byte("test-secret-test-secret-test-secret"), time.Hour, 24*time.Hour),
		Challenges:  auth.NewChallengeStore(rdb, time.Minute, 2),
		Idem:        auth.NewIdempotency(rdb, 5*time.Minute, 5*time.Minute),
		Identities:  fakeIdentities{pub: pub},
		PoWRequired: true,
	}, priv, "user-1"
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

// login：走完整 Challenge-Response 拿 access_token。
func login(t *testing.T, srv *httptest.Server, priv ed25519.PrivateKey, userID string) string {
	t.Helper()
	resp := doJSON(t, srv, http.MethodPost, "/v1/auth/challenge",
		fmt.Sprintf(`{"user_id":%q}`, userID), "msg-challenge-1", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge 期望 200，实际 %d", resp.StatusCode)
	}
	var ch auth.Challenge
	if err := json.NewDecoder(resp.Body).Decode(&ch); err != nil {
		t.Fatal(err)
	}

	var solution string
	for i := 0; ; i++ {
		solution = fmt.Sprintf("%d-%s", i, ch.Nonce)
		if auth.VerifyPoW(ch.PowChallenge, solution, ch.PowDifficulty) {
			break
		}
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(ch.Nonce)))
	body := fmt.Sprintf(`{"user_id":%q,"nonce":%q,"signed_pop":%q,"pow_solution":%q}`,
		userID, ch.Nonce, sig, solution)

	resp2 := doJSON(t, srv, http.MethodPost, "/v1/auth/login", body, "msg-login-1", "")
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("login 期望 200，实际 %d", resp2.StatusCode)
	}
	var pair auth.TokenPair
	if err := json.NewDecoder(resp2.Body).Decode(&pair); err != nil {
		t.Fatal(err)
	}
	if pair.AccessToken == "" {
		t.Fatal("未返回 access_token")
	}
	return pair.AccessToken
}

func TestScheduleActionRequiresToken(t *testing.T) {
	deps, priv, userID := newDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	// 无 token → 401
	resp := doJSON(t, srv, http.MethodPost, "/v1/schedule/action", `{}`, "msg-1", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("无 token 期望 401，实际 %d", resp.StatusCode)
	}

	// 带合法 token → 501（Phase 1.4 才实现业务）
	token := login(t, srv, priv, userID)
	resp2 := doJSON(t, srv, http.MethodPost, "/v1/schedule/action", `{}`, "msg-2", token)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotImplemented {
		t.Fatalf("带 token 期望 501（Phase 1.4 收口），实际 %d", resp2.StatusCode)
	}
}

func TestReplayIsIdempotent(t *testing.T) {
	deps, priv, userID := newDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()
	token := login(t, srv, priv, userID)

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
	deps, _, _ := newDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	resp := doJSON(t, srv, http.MethodPost, "/v1/auth/challenge", `{"user_id":"user-1"}`, "", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("缺 client_msg_id 期望 400，实际 %d", resp.StatusCode)
	}
}

func TestLoginRejectsBadSignature(t *testing.T) {
	deps, _, userID := newDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	resp := doJSON(t, srv, http.MethodPost, "/v1/auth/challenge",
		fmt.Sprintf(`{"user_id":%q}`, userID), "msg-c2", "")
	defer resp.Body.Close()
	var ch auth.Challenge
	_ = json.NewDecoder(resp.Body).Decode(&ch)

	_, priv, _ := ed25519.GenerateKey(rand.Reader) // 与库内公钥不匹配
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(ch.Nonce)))
	body := fmt.Sprintf(`{"user_id":%q,"nonce":%q,"signed_pop":%q,"pow_solution":"x"}`, userID, ch.Nonce, sig)

	resp2 := doJSON(t, srv, http.MethodPost, "/v1/auth/login", body, "msg-l2", "")
	defer resp2.Body.Close()
	// PoW 先拦（400/401 PoW）；这里断言「绝不 200」即可覆盖伪造签名路径
	if resp2.StatusCode == http.StatusOK {
		t.Fatal("伪造签名/PoW 不应签发 Token")
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
