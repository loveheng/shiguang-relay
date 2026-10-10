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
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"shiguang-relay/internal/auth"
	"shiguang-relay/internal/httpapi"
	"shiguang-relay/internal/store"
)

// PG 集成测试：默认跳过，设置 RELAY_TEST_PG_DSN 后运行（OPK 原子弹出必须验真 SQL 行为）。
//   RELAY_TEST_PG_DSN="postgres://relay:relay@localhost:5432/relay?sslmode=disable" go test ./... -count=1

func pgDeps(t *testing.T) (httpapi.Deps, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("RELAY_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("未设置 RELAY_TEST_PG_DSN，跳过 PG 集成测试")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

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
		Identities:          store.PGIdentity{Pool: pool},
		Users:               store.UserStore{Pool: pool},
		Credentials:         store.UserStore{Pool: pool},
		Limiter:             auth.NewRateLimiter(rdb, 100, time.Minute),
		RegisterLimitPerMin: 100,
		PoWRequired:         true,

		Friends:                 store.FriendsStore{Pool: pool},
		FriendInviteLimitPerMin: 100,

		Bundles:     store.BundlesStore{Pool: pool},
		Broadcaster: httpapi.NoopBroadcaster{},

		Deny:   deny,
		Epochs: epochs,
	}, pool
}

// randomID：UUID v4 字符串 —— users.user_id 是 UUID 列，非 UUID 文本会被 PG 拒。
func randomID(prefix string) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	_ = prefix
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

type regInput struct {
	userID   string
	username string
	password string
	priv     ed25519.PrivateKey
	pub      ed25519.PublicKey
}

// randName：生成小写字母/数字的唯一用户名（满足 ^[a-z0-9_]{3,32}$）。
func randName(prefix string) string {
	return prefix + fmt.Sprintf("%x", randomBytes(8))
}

// registerRaw：走完整 Challenge + PoW 完成注册（Plan A：用户名+密码，无 PoP）。
// 返回原始响应；registerUser 在此基础上解析 user_id。
func registerRaw(t *testing.T, srv *httptest.Server, username, password string, opks int, identityPub ed25519.PublicKey) *http.Response {
	t.Helper()
	resp := doJSON(t, srv, http.MethodPost, "/v1/auth/challenge", `{}`, randomID("m"), "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge 失败: %d", resp.StatusCode)
	}
	var ch auth.Challenge
	_ = json.NewDecoder(resp.Body).Decode(&ch)

	var solution string
	for i := 0; ; i++ {
		solution = fmt.Sprintf("%d-%s", i, ch.Nonce)
		if auth.VerifyPoW(ch.PowChallenge, solution, ch.PowDifficulty) {
			break
		}
	}

	opkJSON := make([]string, 0, opks)
	for i := 0; i < opks; i++ {
		opkJSON = append(opkJSON, fmt.Sprintf(
			`{"key_id":"k%d","pub":%q,"signature":%q}`, i,
			base64.StdEncoding.EncodeToString(randomBytes(32)),
			base64.StdEncoding.EncodeToString(randomBytes(64))))
	}
	body := fmt.Sprintf(`{
		"username":%q,"password":%q,
		"identity_key_pub":%q,"signed_prekey_pub":%q,"signed_prekey_sig":%q,
		"nonce":%q,"pow_solution":%q,
		"one_time_prekeys":[%s]}`,
		username, password,
		base64.StdEncoding.EncodeToString(identityPub),
		base64.StdEncoding.EncodeToString(randomBytes(32)),
		base64.StdEncoding.EncodeToString(randomBytes(64)),
		ch.Nonce, solution,
		strings.Join(opkJSON, ","))

	return doJSON(t, srv, http.MethodPost, "/v1/users", body, randomID("m"), "")
}

// registerUser：用户名+密码注册（Plan A）+ 首批 OPK；返回 user_id / 用户名 / 密码 / IK（供 Ticket 签名）。
func registerUser(t *testing.T, srv *httptest.Server, opks int) regInput {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	username := randName("u")
	password := "Pw_" + fmt.Sprintf("%x", randomBytes(4))

	r2 := registerRaw(t, srv, username, password, opks, pub)
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusCreated {
		t.Fatalf("注册期望 201，实际 %d: %s", r2.StatusCode, readAll(t, r2))
	}
	var out struct {
		UserID  string `json:"user_id"`
		Username string `json:"username"`
	}
	_ = json.NewDecoder(r2.Body).Decode(&out)
	return regInput{userID: out.UserID, username: username, password: password, priv: priv, pub: pub}
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func TestRegisterRejectsDuplicateUsername(t *testing.T) {
	deps, _ := pgDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	in := registerUser(t, srv, store.MinInitialPreKeys)
	// 同用户名再注册（完整 challenge+PoW）→ 409 USERNAME_EXISTS
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	r := registerRaw(t, srv, in.username, "Pw_12345", store.MinInitialPreKeys, pub)
	defer r.Body.Close()
	if r.StatusCode != http.StatusConflict {
		t.Fatalf("重复用户名期望 409，实际 %d: %s", r.StatusCode, readAll(t, r))
	}
}

func TestRegisterRejectsWrongPreKeyCount(t *testing.T) {
	deps, _ := pgDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	// 只带 3 个 OPK —— 低于首批下限 10
	r := registerRaw(t, srv, randName("u"), "Pw_12345", 3, pub)
	defer r.Body.Close()
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("OPK 数量越界期望 400，实际 %d", r.StatusCode)
	}
}

func TestPreKeyPopIsExclusiveAndBounded(t *testing.T) {
	deps, _ := pgDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	in := registerUser(t, srv, store.MinInitialPreKeys)

	seen := map[string]bool{}
	for i := 0; i < store.MinInitialPreKeys; i++ {
		resp := doJSON(t, srv, http.MethodGet, "/v1/users/"+in.userID+"/prekey", "", randomID("m"), "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("prekey 期望 200，实际 %d", resp.StatusCode)
		}
		var out struct {
			OneTimePreKeys []struct{ KeyID string `json:"key_id"` } `json:"one_time_prekeys"`
			Remaining      int                                      `json:"remaining_opk"`
			Warning        string                                   `json:"warning"`
			IdentityPub    string                                   `json:"identity_key_pub"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if out.IdentityPub != base64.StdEncoding.EncodeToString(in.pub) {
			t.Fatal("身份公钥与注册时不一致")
		}
		if len(out.OneTimePreKeys) != 1 {
			t.Fatalf("每次应弹出 1 个 OPK，实际 %d", len(out.OneTimePreKeys))
		}
		id := out.OneTimePreKeys[0].KeyID
		if seen[id] {
			t.Fatalf("OPK %s 被重复弹出", id)
		}
		seen[id] = true
		if out.Remaining != store.MinInitialPreKeys-i-1 {
			t.Fatalf("remaining 期望 %d，实际 %d", store.MinInitialPreKeys-i-1, out.Remaining)
		}
	}

	// 空池：仍 200 + 空列表 + OPK_EMPTY_WARNING（v0.1.6 降级口径）
	resp := doJSON(t, srv, http.MethodGet, "/v1/users/"+in.userID+"/prekey", "", randomID("m"), "")
	defer resp.Body.Close()
	var out struct {
		OneTimePreKeys []map[string]string `json:"one_time_prekeys"`
		Warning        string              `json:"warning"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if len(out.OneTimePreKeys) != 0 || out.Warning != "OPK_EMPTY_WARNING" {
		t.Fatalf("空池应返回空列表 + OPK_EMPTY_WARNING，实际 %+v", out)
	}
}

func TestPreKeyConcurrentPopNoDuplicate(t *testing.T) {
	deps, pool := pgDeps(t)
	in := registerUser(t, httptest.NewServer(httpapi.NewRouter(deps)), store.MaxInitialPreKeys)

	// 直接压数据层（HTTP 层并发已被幂等中间件干扰，这里验 SQL 的 SKIP LOCKED 语义）
	users := store.UserStore{Pool: pool}
	var mu sync.Mutex
	got := map[string]int{}
	var wg sync.WaitGroup
	for i := 0; i < store.MaxInitialPreKeys; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pk, _, err := users.PopOneTimePreKey(context.Background(), in.userID)
			if err != nil {
				return
			}
			if pk == nil {
				return
			}
			mu.Lock()
			got[pk.KeyID]++
			mu.Unlock()
		}()
	}
	wg.Wait()

	for id, n := range got {
		if n != 1 {
			t.Fatalf("OPK %s 被并发弹出 %d 次（应恰好 1 次）", id, n)
		}
	}
	if len(got) != store.MaxInitialPreKeys {
		t.Fatalf("应弹出 %d 个互不相同的 OPK，实际 %d", store.MaxInitialPreKeys, len(got))
	}
}

func TestRefillPreKeysRequiresAuthAndWorks(t *testing.T) {
	deps, _ := pgDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	in := registerUser(t, srv, store.MinInitialPreKeys)

	// 未带 token → 401
	body := fmt.Sprintf(`{"one_time_prekeys":[{"key_id":"r1","pub":%q,"signature":%q}]}`,
		base64.StdEncoding.EncodeToString(randomBytes(32)),
		base64.StdEncoding.EncodeToString(randomBytes(64)))
	r := doJSON(t, srv, http.MethodPost, "/v1/users/me/prekeys", body, randomID("m"), "")
	r.Body.Close()
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("补仓未鉴权期望 401，实际 %d", r.StatusCode)
	}

	token := login(t, srv, in.username, in.password)
	r2 := doJSON(t, srv, http.MethodPost, "/v1/users/me/prekeys", body, randomID("m"), token)
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("补仓期望 200，实际 %d: %s", r2.StatusCode, readAll(t, r2))
	}

	// 超限批量 → 400
	big := make([]string, store.MaxRefillPreKeys+1)
	for i := range big {
		big[i] = fmt.Sprintf(`{"key_id":"b%d","pub":%q,"signature":%q}`, i,
			base64.StdEncoding.EncodeToString(randomBytes(32)),
			base64.StdEncoding.EncodeToString(randomBytes(64)))
	}
	bigBody := fmt.Sprintf(`{"one_time_prekeys":[%s]}`, strings.Join(big, ","))
	r3 := doJSON(t, srv, http.MethodPost, "/v1/users/me/prekeys", bigBody, randomID("m"), token)
	defer r3.Body.Close()
	if r3.StatusCode != http.StatusBadRequest {
		t.Fatalf("超限补仓期望 400，实际 %d", r3.StatusCode)
	}
}
