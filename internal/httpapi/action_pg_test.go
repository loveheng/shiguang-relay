package httpapi_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"

	"shiguang-relay/internal/auth"
	"shiguang-relay/internal/httpapi"
	"shiguang-relay/internal/store"
)

// 协同动作集成测试（需 RELAY_TEST_PG_DSN）。
// 验收线（collab-implementation §2 1.4）：并发 10 请求同 Bundle 无 seq 冲突。

// makeFriends：x 扫码 y 的名片并发起邀请，y 手动接受（pending → accepted）。
func makeFriends(t *testing.T, srv *httptest.Server, x, y regInput) {
	t.Helper()
	tokenX := login(t, srv, x.priv, x.userID)
	tokenY := login(t, srv, y.priv, y.userID)

	ticket := auth.FriendshipTicket{
		IssuerUserID:  y.userID,
		SubjectUserID: x.userID,
		Nonce:         randomID("n"),
		ExpiresAt:     time.Now().Add(time.Hour).Unix(),
	}
	r := doJSON(t, srv, http.MethodPost, "/v1/friends/invite",
		inviteBody(ticket, y.priv, ""), randomID("m"), tokenX)
	defer r.Body.Close()
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("建联邀请失败: %d %s", r.StatusCode, readAll(t, r))
	}
	r2 := doJSON(t, srv, http.MethodPost, "/v1/friends/accept",
		fmt.Sprintf(`{"invite_id":%q,"accept":true}`, x.userID+":"+y.userID), randomID("m"), tokenY)
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("接受邀请失败: %d %s", r2.StatusCode, readAll(t, r2))
	}
}

func proposeBundle(t *testing.T, srv *httptest.Server, token string, participants []string, cipher string) map[string]any {
	t.Helper()
	uids := make([]string, 0, len(participants))
	for _, p := range participants {
		uids = append(uids, fmt.Sprintf("%q", p))
	}
	body := fmt.Sprintf(`{"action":"PROPOSE","cipher":%q,"proposal_type":"CONSENSUS",
		"participant_uids":[%s],"topology":{"steps":[{"step_id":"s1","required_uids":[%s],"threshold":1}]},"quorum":1}`,
		cipher, join(uids), join(uids))
	r := doJSON(t, srv, http.MethodPost, "/v1/schedule/action", body, randomID("m"), token)
	defer r.Body.Close()
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("建包期望 201，实际 %d: %s", r.StatusCode, readAll(t, r))
	}
	var out map[string]any
	_ = json.NewDecoder(r.Body).Decode(&out)
	return out
}

func join(in []string) string {
	out := ""
	for i, s := range in {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}

func TestScheduleActionConcurrentSeqNoConflict(t *testing.T) {
	deps, _ := pgDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	a := registerUser(t, srv, store.MinInitialPreKeys)
	b := registerUser(t, srv, store.MinInitialPreKeys)
	makeFriends(t, srv, a, b)

	tokenA := login(t, srv, a.priv, a.userID)
	tokenB := login(t, srv, b.priv, b.userID)

	res := proposeBundle(t, srv, tokenA, []string{b.userID}, base64.StdEncoding.EncodeToString([]byte("propose-cipher")))
	bundleID, _ := res["bundle_id"].(string)
	if bundleID == "" {
		t.Fatalf("未返回 bundle_id: %+v", res)
	}
	if seq, _ := res["seq_id"].(float64); seq != 1 {
		t.Fatalf("PROPOSE 应为 seq 1，实际 %v", seq)
	}

	// 10 并发追加事件：seq 必须严格递增且互不重复
	const n = 10
	var wg sync.WaitGroup
	var mu sync.Mutex
	seqs := make([]int64, 0, n)
	codes := make([]int, 0, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			token := tokenA
			if i%2 == 1 {
				token = tokenB
			}
			body := fmt.Sprintf(`{"bundle_id":%q,"action":"ACCEPT","cipher":%q}`,
				bundleID, base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("cipher-%d", i))))
			r := doJSON(t, srv, http.MethodPost, "/v1/schedule/action", body, randomID("m"), token)
			defer r.Body.Close()
			var out map[string]any
			_ = json.NewDecoder(r.Body).Decode(&out)
			mu.Lock()
			codes = append(codes, r.StatusCode)
			if v, ok := out["seq_id"].(float64); ok {
				seqs = append(seqs, int64(v))
			}
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	if len(seqs) != n {
		t.Fatalf("并发 %d 次应全部成功，实际成功 %d（状态码 %v）", n, len(seqs), codes)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	seen := map[int64]bool{}
	for i, s := range seqs {
		if seen[s] {
			t.Fatalf("seq %d 被重复分配（并发同号冲突）", s)
		}
		seen[s] = true
		if s != int64(i+2) { // PROPOSE 已占 1
			t.Fatalf("seq 应连续 2..%d，实际第 %d 个为 %d", n+1, i, s)
		}
	}
}

func TestScheduleActionGuards(t *testing.T) {
	deps, _ := pgDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	a := registerUser(t, srv, store.MinInitialPreKeys)
	b := registerUser(t, srv, store.MinInitialPreKeys)
	c := registerUser(t, srv, store.MinInitialPreKeys) // 非成员
	makeFriends(t, srv, a, b)

	tokenA := login(t, srv, a.priv, a.userID)
	tokenC := login(t, srv, c.priv, c.userID)

	res := proposeBundle(t, srv, tokenA, []string{b.userID}, base64.StdEncoding.EncodeToString([]byte("c")))
	bundleID, _ := res["bundle_id"].(string)

	// 非成员 → 403
	r1 := doJSON(t, srv, http.MethodPost, "/v1/schedule/action",
		fmt.Sprintf(`{"bundle_id":%q,"action":"ACCEPT","cipher":%q}`, bundleID,
			base64.StdEncoding.EncodeToString([]byte("x"))), randomID("m"), tokenC)
	r1.Body.Close()
	if r1.StatusCode != http.StatusForbidden {
		t.Fatalf("非成员期望 403，实际 %d", r1.StatusCode)
	}

	// 未知动作 → 400
	r2 := doJSON(t, srv, http.MethodPost, "/v1/schedule/action",
		fmt.Sprintf(`{"bundle_id":%q,"action":"WHATEVER","cipher":%q}`, bundleID,
			base64.StdEncoding.EncodeToString([]byte("x"))), randomID("m"), tokenA)
	r2.Body.Close()
	if r2.StatusCode != http.StatusBadRequest {
		t.Fatalf("未知动作期望 400，实际 %d", r2.StatusCode)
	}

	// 事实三动作绕过 base_revision 乐观锁（v0.1.3）→ 陈旧 revision 仍放行
	r3 := doJSON(t, srv, http.MethodPost, "/v1/schedule/action",
		fmt.Sprintf(`{"bundle_id":%q,"action":"ATTACH_FACT","cipher":%q,"expected_revision":999}`, bundleID,
			base64.StdEncoding.EncodeToString([]byte("fact"))), randomID("m"), tokenA)
	r3.Body.Close()
	if r3.StatusCode != http.StatusOK {
		t.Fatalf("事实动作应绕过乐观锁，期望 200，实际 %d", r3.StatusCode)
	}

	// 非事实动作 + 陈旧 revision → 409 STALE_REVISION
	r4 := doJSON(t, srv, http.MethodPost, "/v1/schedule/action",
		fmt.Sprintf(`{"bundle_id":%q,"action":"ACCEPT","cipher":%q,"expected_revision":999}`, bundleID,
			base64.StdEncoding.EncodeToString([]byte("x"))), randomID("m"), tokenA)
	r4.Body.Close()
	if r4.StatusCode != http.StatusConflict {
		t.Fatalf("陈旧 revision 期望 409，实际 %d", r4.StatusCode)
	}

	// FORCE_FINALIZE 落槌（发起人）→ CONFIRMED
	r5 := doJSON(t, srv, http.MethodPost, "/v1/schedule/action",
		fmt.Sprintf(`{"bundle_id":%q,"action":"FORCE_FINALIZE","cipher":%q}`, bundleID,
			base64.StdEncoding.EncodeToString([]byte("final"))), randomID("m"), tokenA)
	r5.Body.Close()
	if r5.StatusCode != http.StatusOK {
		t.Fatalf("落槌期望 200，实际 %d: %s", r5.StatusCode, readAll(t, r5))
	}

	// 已敲定 → 再提交一律 409（含第二次落槌）
	r6 := doJSON(t, srv, http.MethodPost, "/v1/schedule/action",
		fmt.Sprintf(`{"bundle_id":%q,"action":"FORCE_FINALIZE","cipher":%q}`, bundleID,
			base64.StdEncoding.EncodeToString([]byte("final2"))), randomID("m"), tokenA)
	r6.Body.Close()
	if r6.StatusCode != http.StatusConflict {
		t.Fatalf("已敲定期望 409，实际 %d", r6.StatusCode)
	}
	r7 := doJSON(t, srv, http.MethodPost, "/v1/schedule/action",
		fmt.Sprintf(`{"bundle_id":%q,"action":"ACCEPT","cipher":%q}`, bundleID,
			base64.StdEncoding.EncodeToString([]byte("x"))), randomID("m"), tokenA)
	r7.Body.Close()
	if r7.StatusCode != http.StatusConflict {
		t.Fatalf("已敲定后普通动作期望 409，实际 %d", r7.StatusCode)
	}
}

func TestProposeRejectsTooManyMembers(t *testing.T) {
	deps, _ := pgDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	a := registerUser(t, srv, store.MinInitialPreKeys)
	tokenA := login(t, srv, a.priv, a.userID)

	uids := make([]string, store.MaxBundleMembers) // + 发起人自己 = 超限
	for i := range uids {
		uids[i] = fmt.Sprintf("%q", randomID("u"))
	}
	body := fmt.Sprintf(`{"action":"PROPOSE","cipher":%q,"participant_uids":[%s]}`,
		base64.StdEncoding.EncodeToString([]byte("c")), join(uids))
	r := doJSON(t, srv, http.MethodPost, "/v1/schedule/action", body, randomID("m"), tokenA)
	defer r.Body.Close()
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("成员超限期望 400，实际 %d", r.StatusCode)
	}
}

func TestProposeRequiresAcceptedFriendship(t *testing.T) {
	deps, _ := pgDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	a := registerUser(t, srv, store.MinInitialPreKeys)
	stranger := registerUser(t, srv, store.MinInitialPreKeys) // 与 A 无好友关系
	tokenA := login(t, srv, a.priv, a.userID)

	body := fmt.Sprintf(`{"action":"PROPOSE","cipher":%q,"participant_uids":[%q]}`,
		base64.StdEncoding.EncodeToString([]byte("c")), stranger.userID)
	r := doJSON(t, srv, http.MethodPost, "/v1/schedule/action", body, randomID("m"), tokenA)
	defer r.Body.Close()
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("拉陌生人建包期望 403，实际 %d", r.StatusCode)
	}
}
