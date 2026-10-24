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
	tokenX := login(t, srv, x.username, x.password)
	tokenY := login(t, srv, y.username, y.password)

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

	tokenA := login(t, srv, a.username, a.password)
	tokenB := login(t, srv, b.username, b.password)

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

	tokenA := login(t, srv, a.username, a.password)
	tokenC := login(t, srv, c.username, c.password)

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
	tokenA := login(t, srv, a.username, a.password)

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
	tokenA := login(t, srv, a.username, a.password)

	body := fmt.Sprintf(`{"action":"PROPOSE","cipher":%q,"participant_uids":[%q]}`,
		base64.StdEncoding.EncodeToString([]byte("c")), stranger.userID)
	r := doJSON(t, srv, http.MethodPost, "/v1/schedule/action", body, randomID("m"), tokenA)
	defer r.Body.Close()
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("拉陌生人建包期望 403，实际 %d", r.StatusCode)
	}
}

// 敲定后生命周期白名单（2026-10-25 拍板 §4.3/§4.5）：CONFIRMED 后仅
// PATCH_STEP_TIME（发起人独占）与 LEAVE（成员平权、发起人禁投）可过终态门禁；
// CANCELLED 一律拦。
func TestPatchStepTimeAndLeaveAfterConfirm(t *testing.T) {
	deps, _ := pgDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	a := registerUser(t, srv, store.MinInitialPreKeys)
	b := registerUser(t, srv, store.MinInitialPreKeys)
	makeFriends(t, srv, a, b)
	tokenA := login(t, srv, a.username, a.password)
	tokenB := login(t, srv, b.username, b.password)

	res := proposeBundle(t, srv, tokenA, []string{b.userID}, base64.StdEncoding.EncodeToString([]byte("c")))
	bundleID, _ := res["bundle_id"].(string)

	act := func(token, action string) (int, map[string]any) {
		body := fmt.Sprintf(`{"bundle_id":%q,"action":%q,"cipher":%q}`,
			bundleID, action, base64.StdEncoding.EncodeToString([]byte(action)))
		r := doJSON(t, srv, http.MethodPost, "/v1/schedule/action", body, randomID("m"), token)
		defer r.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(r.Body).Decode(&out)
		return r.StatusCode, out
	}

	// 落槌 → CONFIRMED
	if code, _ := act(tokenA, "FORCE_FINALIZE"); code != http.StatusOK {
		t.Fatalf("落槌期望 200，实际 %d", code)
	}

	// 敲定后普通动作仍 409
	if code, _ := act(tokenA, "ACCEPT"); code != http.StatusConflict {
		t.Fatalf("敲定后普通动作期望 409，实际 %d", code)
	}

	// PATCH_STEP_TIME：非发起人 → 403 NOT_INITIATOR
	code, out := act(tokenB, "PATCH_STEP_TIME")
	if code != http.StatusForbidden || out["error_code"] != "NOT_INITIATOR" {
		t.Fatalf("非发起人改期期望 403/NOT_INITIATOR，实际 %d/%v", code, out["error_code"])
	}

	// PATCH_STEP_TIME：发起人 → 200 且 status 保持 CONFIRMED
	code, out = act(tokenA, "PATCH_STEP_TIME")
	if code != http.StatusOK || out["status"] != "CONFIRMED" {
		t.Fatalf("发起人单步骤改期期望 200/CONFIRMED，实际 %d/%v", code, out["status"])
	}

	// LEAVE：发起人 → 403 INITIATOR_CANNOT_LEAVE
	code, out = act(tokenA, "LEAVE")
	if code != http.StatusForbidden || out["error_code"] != "INITIATOR_CANNOT_LEAVE" {
		t.Fatalf("发起人退出期望 403/INITIATOR_CANNOT_LEAVE，实际 %d/%v", code, out["error_code"])
	}

	// LEAVE：成员 → 200，status 保持 CONFIRMED
	code, out = act(tokenB, "LEAVE")
	if code != http.StatusOK || out["status"] != "CONFIRMED" {
		t.Fatalf("成员自主退出期望 200/CONFIRMED，实际 %d/%v", code, out["status"])
	}
}

// 终态 CANCELLED 对白名单动作同样关闭（§4.3：CANCELLED/EXPIRED 一律拦）。
func TestTerminalGateClosesAfterCancel(t *testing.T) {
	deps, _ := pgDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	a := registerUser(t, srv, store.MinInitialPreKeys)
	b := registerUser(t, srv, store.MinInitialPreKeys)
	makeFriends(t, srv, a, b)
	tokenA := login(t, srv, a.username, a.password)
	tokenB := login(t, srv, b.username, b.password)

	res := proposeBundle(t, srv, tokenA, []string{b.userID}, base64.StdEncoding.EncodeToString([]byte("c")))
	bundleID, _ := res["bundle_id"].(string)

	act := func(token, action string) int {
		body := fmt.Sprintf(`{"bundle_id":%q,"action":%q,"cipher":%q}`,
			bundleID, action, base64.StdEncoding.EncodeToString([]byte(action)))
		r := doJSON(t, srv, http.MethodPost, "/v1/schedule/action", body, randomID("m"), token)
		defer r.Body.Close()
		return r.StatusCode
	}

	if code := act(tokenA, "CANCEL"); code != http.StatusOK {
		t.Fatalf("取消期望 200，实际 %d", code)
	}
	for _, action := range []string{"PATCH_STEP_TIME", "LEAVE", "REOPEN"} {
		if code := act(tokenB, action); code != http.StatusConflict {
			t.Fatalf("取消后 %s 期望 409，实际 %d", action, code)
		}
	}
}

// proposeTyped：指定 proposal_type 建包（REOPEN 权限分流测试用）。
func proposeTyped(t *testing.T, srv *httptest.Server, token, ptype string, participants []string, cipher string) map[string]any {
	t.Helper()
	uids := make([]string, 0, len(participants))
	for _, p := range participants {
		uids = append(uids, fmt.Sprintf("%q", p))
	}
	body := fmt.Sprintf(`{"action":"PROPOSE","cipher":%q,"proposal_type":%q,"participant_uids":[%s]}`,
		cipher, ptype, join(uids))
	r := doJSON(t, srv, http.MethodPost, "/v1/schedule/action", body, randomID("m"), token)
	defer r.Body.Close()
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("建包期望 201，实际 %d: %s", r.StatusCode, readAll(t, r))
	}
	var out map[string]any
	_ = json.NewDecoder(r.Body).Decode(&out)
	return out
}

func actJSON(t *testing.T, srv *httptest.Server, token, bundleID, body string) (int, map[string]any) {
	t.Helper()
	r := doJSON(t, srv, http.MethodPost, "/v1/schedule/action", body, randomID("m"), token)
	defer r.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(r.Body).Decode(&out)
	return r.StatusCode, out
}

// ADD_MEMBER 准入严管（v0.1.10）：发起人独占 + 被加人与发起人双向 accepted（对齐 PROPOSE §1.7）。
func TestAddMemberInitiatorOnlyAndFriendAdmission(t *testing.T) {
	deps, _ := pgDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	a := registerUser(t, srv, store.MinInitialPreKeys) // 发起人
	b := registerUser(t, srv, store.MinInitialPreKeys) // 包内普通成员
	c := registerUser(t, srv, store.MinInitialPreKeys) // 与 A 双向好友（可被拉入）
	d := registerUser(t, srv, store.MinInitialPreKeys) // 与 A 非好友（准入拒绝对象）
	makeFriends(t, srv, a, b)
	makeFriends(t, srv, a, c)

	tokenA := login(t, srv, a.username, a.password)
	tokenB := login(t, srv, b.username, b.password)

	res := proposeBundle(t, srv, tokenA, []string{b.userID}, base64.StdEncoding.EncodeToString([]byte("c")))
	bundleID, _ := res["bundle_id"].(string)
	cipher := base64.StdEncoding.EncodeToString([]byte("add"))

	addBody := fmt.Sprintf(`{"bundle_id":%q,"action":"ADD_MEMBER","cipher":%q,"add_member_uids":[%q]}`,
		bundleID, cipher, d.userID)

	// 普通成员（即便被加人是自己的好友）→ 403 NOT_INITIATOR
	code, out := actJSON(t, srv, tokenB, bundleID,
		fmt.Sprintf(`{"bundle_id":%q,"action":"ADD_MEMBER","cipher":%q,"add_member_uids":[%q]}`,
			bundleID, cipher, c.userID))
	if code != http.StatusForbidden || out["error_code"] != "NOT_INITIATOR" {
		t.Fatalf("非发起人加人期望 403/NOT_INITIATOR，实际 %d/%v", code, out["error_code"])
	}

	// 发起人拉非好友 → 403 NOT_PARTICIPANT（对齐 PROPOSE 准入）
	code, out = actJSON(t, srv, tokenA, bundleID, addBody)
	if code != http.StatusForbidden || out["error_code"] != "NOT_PARTICIPANT" {
		t.Fatalf("拉非好友期望 403/NOT_PARTICIPANT，实际 %d/%v", code, out["error_code"])
	}

	// 发起人拉双向好友 → 200 且并入 participant_uids
	code, out = actJSON(t, srv, tokenA, bundleID,
		fmt.Sprintf(`{"bundle_id":%q,"action":"ADD_MEMBER","cipher":%q,"add_member_uids":[%q]}`,
			bundleID, cipher, c.userID))
	if code != http.StatusOK {
		t.Fatalf("发起人加好友期望 200，实际 %d: %v", code, out)
	}
	var inBundle bool
	if err := deps.Bundles.Pool.QueryRow(t.Context(),
		`SELECT $1::uuid = ANY(participant_uids) FROM bundles WHERE bundle_id=$2`, c.userID, bundleID).Scan(&inBundle); err != nil {
		t.Fatal(err)
	}
	if !inBundle {
		t.Fatal("被加人应已并入 participant_uids")
	}
}

// TRANSFER_INITIATOR 契约补丁（v0.1.10）：明文 transfer_to 驱动服务端改写 initiator_id；
// 转移后旧发起人失权、新发起人可落槌。
func TestTransferInitiatorRewritesInitiator(t *testing.T) {
	deps, _ := pgDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	a := registerUser(t, srv, store.MinInitialPreKeys)
	b := registerUser(t, srv, store.MinInitialPreKeys)
	c := registerUser(t, srv, store.MinInitialPreKeys) // 非成员
	makeFriends(t, srv, a, b)
	tokenA := login(t, srv, a.username, a.password)
	tokenB := login(t, srv, b.username, b.password)

	res := proposeBundle(t, srv, tokenA, []string{b.userID}, base64.StdEncoding.EncodeToString([]byte("c")))
	bundleID, _ := res["bundle_id"].(string)
	cipher := base64.StdEncoding.EncodeToString([]byte("t"))

	transfer := func(token, to string) (int, map[string]any) {
		return actJSON(t, srv, token, bundleID,
			fmt.Sprintf(`{"bundle_id":%q,"action":"TRANSFER_INITIATOR","cipher":%q,"transfer_to":%q}`,
				bundleID, cipher, to))
	}

	// 非发起人发起转移 → 403
	code, out := transfer(tokenB, b.userID)
	if code != http.StatusForbidden || out["error_code"] != "NOT_INITIATOR" {
		t.Fatalf("非发起人转移期望 403/NOT_INITIATOR，实际 %d/%v", code, out["error_code"])
	}

	// transfer_to 缺失 → 400
	code, out = actJSON(t, srv, tokenA, bundleID,
		fmt.Sprintf(`{"bundle_id":%q,"action":"TRANSFER_INITIATOR","cipher":%q}`, bundleID, cipher))
	if code != http.StatusBadRequest || out["error_code"] != "INVALID_REQUEST" {
		t.Fatalf("缺 transfer_to 期望 400/INVALID_REQUEST，实际 %d/%v", code, out["error_code"])
	}

	// transfer_to 非包内成员 → 403 NOT_PARTICIPANT
	code, out = transfer(tokenA, c.userID)
	if code != http.StatusForbidden || out["error_code"] != "NOT_PARTICIPANT" {
		t.Fatalf("转移给非成员期望 403/NOT_PARTICIPANT，实际 %d/%v", code, out["error_code"])
	}

	// 发起人转移给包内成员 → 200 且 initiator_id 已改写
	code, _ = transfer(tokenA, b.userID)
	if code != http.StatusOK {
		t.Fatalf("转移期望 200，实际 %d", code)
	}
	var initiator string
	if err := deps.Bundles.Pool.QueryRow(t.Context(),
		`SELECT initiator_id::text FROM bundles WHERE bundle_id=$1`, bundleID).Scan(&initiator); err != nil {
		t.Fatal(err)
	}
	if initiator != b.userID {
		t.Fatalf("initiator_id 应已改写为 %s，实际 %s", b.userID, initiator)
	}

	// 旧发起人 CANCEL → 403；新发起人落槌 → 200
	code, out = actJSON(t, srv, tokenA, bundleID,
		fmt.Sprintf(`{"bundle_id":%q,"action":"CANCEL","cipher":%q}`, bundleID, cipher))
	if code != http.StatusForbidden || out["error_code"] != "NOT_INITIATOR" {
		t.Fatalf("旧发起人 CANCEL 期望 403/NOT_INITIATOR，实际 %d/%v", code, out["error_code"])
	}
	code, out = actJSON(t, srv, tokenB, bundleID,
		fmt.Sprintf(`{"bundle_id":%q,"action":"FORCE_FINALIZE","cipher":%q}`, bundleID, cipher))
	if code != http.StatusOK || out["status"] != "CONFIRMED" {
		t.Fatalf("新发起人落槌期望 200/CONFIRMED，实际 %d/%v", code, out["status"])
	}
}

// MEMBER_REMOVED 最小修复（v0.1.10）：发起人独占 + 明文 remove_member_uids +
// 移出 participant_uids（被移除者即刻失去包内 ACL；信封行保留供离线回放；
// 全语义 REKEY 连带挂账 §5.3.1）。
func TestMemberRemovedEvictsParticipant(t *testing.T) {
	deps, _ := pgDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	a := registerUser(t, srv, store.MinInitialPreKeys)
	b := registerUser(t, srv, store.MinInitialPreKeys)
	makeFriends(t, srv, a, b)
	tokenA := login(t, srv, a.username, a.password)
	tokenB := login(t, srv, b.username, b.password)

	res := proposeBundle(t, srv, tokenA, []string{b.userID}, base64.StdEncoding.EncodeToString([]byte("c")))
	bundleID, _ := res["bundle_id"].(string)
	cipher := base64.StdEncoding.EncodeToString([]byte("rm"))

	// 非发起人移除 → 403
	code, out := actJSON(t, srv, tokenB, bundleID,
		fmt.Sprintf(`{"bundle_id":%q,"action":"MEMBER_REMOVED","cipher":%q,"remove_member_uids":[%q]}`,
			bundleID, cipher, a.userID))
	if code != http.StatusForbidden || out["error_code"] != "NOT_INITIATOR" {
		t.Fatalf("非发起人移除期望 403/NOT_INITIATOR，实际 %d/%v", code, out["error_code"])
	}

	// 发起人移除成员 → 200 且移出 participant_uids
	code, _ = actJSON(t, srv, tokenA, bundleID,
		fmt.Sprintf(`{"bundle_id":%q,"action":"MEMBER_REMOVED","cipher":%q,"remove_member_uids":[%q]}`,
			bundleID, cipher, b.userID))
	if code != http.StatusOK {
		t.Fatalf("发起人移除期望 200，实际 %d", code)
	}
	var stillIn bool
	if err := deps.Bundles.Pool.QueryRow(t.Context(),
		`SELECT $1::uuid = ANY(participant_uids) FROM bundles WHERE bundle_id=$2`, b.userID, bundleID).Scan(&stillIn); err != nil {
		t.Fatal(err)
	}
	if stillIn {
		t.Fatal("被移除者应已移出 participant_uids")
	}

	// 被移除者后续动作 → 403 NOT_PARTICIPANT
	code, out = actJSON(t, srv, tokenB, bundleID,
		fmt.Sprintf(`{"bundle_id":%q,"action":"VOTE","cipher":%q}`, bundleID, cipher))
	if code != http.StatusForbidden || out["error_code"] != "NOT_PARTICIPANT" {
		t.Fatalf("被移除者动作期望 403/NOT_PARTICIPANT，实际 %d/%v", code, out["error_code"])
	}

	// 旧写法（add_member_uids 复用传被移除者）不再生效：无 remove_member_uids 时无人被移出
	code, _ = actJSON(t, srv, tokenA, bundleID,
		fmt.Sprintf(`{"bundle_id":%q,"action":"MEMBER_REMOVED","cipher":%q,"add_member_uids":[%q]}`,
			bundleID, cipher, a.userID))
	if code != http.StatusOK {
		t.Fatalf("MEMBER_REMOVED 期望 200，实际 %d", code)
	}
	var initiatorIn bool
	if err := deps.Bundles.Pool.QueryRow(t.Context(),
		`SELECT $1::uuid = ANY(participant_uids) FROM bundles WHERE bundle_id=$2`, a.userID, bundleID).Scan(&initiatorIn); err != nil {
		t.Fatal(err)
	}
	if !initiatorIn {
		t.Fatal("add_member_uids 脏复用不应移出成员")
	}
}

// REOPEN 终态门禁缺口实装（v0.1.10，§4.3/§4.4）：白名单第三动作，仅 CONFIRMED 态放行；
// 权限按 proposal_type 分流（DIRECTIVE=发起人独占 / CONSENSUS=包内平权）；
// 通过后显式置 STALLED，普通动作重新可入（显式门禁转移行，非状态推导）。
func TestReopenAfterConfirm(t *testing.T) {
	deps, _ := pgDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	a := registerUser(t, srv, store.MinInitialPreKeys)
	b := registerUser(t, srv, store.MinInitialPreKeys)
	makeFriends(t, srv, a, b)
	tokenA := login(t, srv, a.username, a.password)
	tokenB := login(t, srv, b.username, b.password)
	cipher := base64.StdEncoding.EncodeToString([]byte("r"))

	act := func(token, bundleID, action string) (int, map[string]any) {
		return actJSON(t, srv, token, bundleID,
			fmt.Sprintf(`{"bundle_id":%q,"action":%q,"cipher":%q}`, bundleID, action, cipher))
	}

	// —— Directive：REOPEN 发起人独占（§4.3）——
	res := proposeTyped(t, srv, tokenA, "DIRECTIVE", []string{b.userID}, cipher)
	dBundle, _ := res["bundle_id"].(string)
	// 非 CONFIRMED 态（PROPOSED）REOPEN → 409 REOPEN_INVALID_STATE（仅 CONFIRMED 态放行）
	code, out := act(tokenB, dBundle, "REOPEN")
	if code != http.StatusConflict || out["error_code"] != "REOPEN_INVALID_STATE" {
		t.Fatalf("PROPOSED 态 REOPEN 期望 409/REOPEN_INVALID_STATE，实际 %d/%v", code, out["error_code"])
	}
	if code, _ := act(tokenA, dBundle, "FORCE_FINALIZE"); code != http.StatusOK {
		t.Fatalf("落槌期望 200，实际 %d", code)
	}
	code, out = act(tokenB, dBundle, "REOPEN")
	if code != http.StatusForbidden || out["error_code"] != "NOT_INITIATOR" {
		t.Fatalf("Directive 成员 REOPEN 期望 403/NOT_INITIATOR，实际 %d/%v", code, out["error_code"])
	}
	code, out = act(tokenA, dBundle, "REOPEN")
	if code != http.StatusOK || out["status"] != "STALLED" {
		t.Fatalf("Directive 发起人 REOPEN 期望 200/STALLED，实际 %d/%v", code, out["status"])
	}
	// 重开后普通动作重新可入
	code, _ = act(tokenB, dBundle, "ACCEPT")
	if code != http.StatusOK {
		t.Fatalf("重开后 ACCEPT 期望 200，实际 %d", code)
	}
	// STALLED 态不可重复 REOPEN（409 REOPEN_INVALID_STATE，防无意义重开刷流水）
	code, out = act(tokenA, dBundle, "REOPEN")
	if code != http.StatusConflict || out["error_code"] != "REOPEN_INVALID_STATE" {
		t.Fatalf("STALLED 态重复 REOPEN 期望 409/REOPEN_INVALID_STATE，实际 %d/%v", code, out["error_code"])
	}

	// —— Consensus：REOPEN 包内平权（§4.4）——
	res = proposeBundle(t, srv, tokenA, []string{b.userID}, cipher)
	cBundle, _ := res["bundle_id"].(string)
	if code, _ := act(tokenA, cBundle, "FORCE_FINALIZE"); code != http.StatusOK {
		t.Fatalf("落槌期望 200，实际 %d", code)
	}
	code, out = act(tokenB, cBundle, "REOPEN")
	if code != http.StatusOK || out["status"] != "STALLED" {
		t.Fatalf("Consensus 成员 REOPEN 期望 200/STALLED，实际 %d/%v", code, out["status"])
	}

	// —— CANCELLED 后 REOPEN 同样被终态门禁拦（CONFIRMED→STALLED 仅此一行）——
	code, _ = act(tokenA, cBundle, "CANCEL")
	if code != http.StatusOK {
		t.Fatalf("取消期望 200，实际 %d", code)
	}
	code, _ = act(tokenB, cBundle, "REOPEN")
	if code != http.StatusConflict {
		t.Fatalf("取消后 REOPEN 期望 409，实际 %d", code)
	}
}

// base_revision 案A拍板（2026-10-25，§5.4）：定型 bundle 级结构版本——
// 每个非事实动作自增 1、事实三动作豁免（不校验不自增，v0.1.3）；校验 opt-in
// （仅显式携带 expected_revision 才比对，普通平权动作不携带永不互打回，防惊群）。
func TestBaseRevisionBundleLevelOptIn(t *testing.T) {
	deps, _ := pgDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	a := registerUser(t, srv, store.MinInitialPreKeys)
	b := registerUser(t, srv, store.MinInitialPreKeys)
	makeFriends(t, srv, a, b)
	tokenA := login(t, srv, a.username, a.password)
	tokenB := login(t, srv, b.username, b.password)

	res := proposeBundle(t, srv, tokenA, []string{b.userID}, base64.StdEncoding.EncodeToString([]byte("c")))
	bundleID, _ := res["bundle_id"].(string)
	cipher := base64.StdEncoding.EncodeToString([]byte("rev"))

	rev := func() int {
		t.Helper()
		var r int
		if err := deps.Bundles.Pool.QueryRow(t.Context(),
			`SELECT base_revision FROM bundles WHERE bundle_id=$1`, bundleID).Scan(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}

	// PROPOSE 落包后基线为 1（seq:1 事件不重复自增）
	if r := rev(); r != 1 {
		t.Fatalf("建包后 base_revision 期望 1，实际 %d", r)
	}

	// 非事实动作不携带 expected_revision（opt-in）→ 200 且恰好自增 1
	code, out := actJSON(t, srv, tokenB, bundleID,
		fmt.Sprintf(`{"bundle_id":%q,"action":"VOTE","cipher":%q}`, bundleID, cipher))
	if code != http.StatusOK {
		t.Fatalf("不带 expected_revision 的平权动作期望 200，实际 %d: %v", code, out)
	}
	if r := rev(); r != 2 {
		t.Fatalf("一次非事实成功动作后 base_revision 期望 2，实际 %d", r)
	}

	// 陈旧 expected_revision + 非事实动作 → 409 STALE_REVISION，且失败动作不推进计数
	code, out = actJSON(t, srv, tokenB, bundleID,
		fmt.Sprintf(`{"bundle_id":%q,"action":"VOTE","cipher":%q,"expected_revision":1}`, bundleID, cipher))
	if code != http.StatusConflict || out["error_code"] != "STALE_REVISION" {
		t.Fatalf("陈旧 revision 期望 409/STALE_REVISION，实际 %d/%v", code, out["error_code"])
	}
	if r := rev(); r != 2 {
		t.Fatalf("被打回的动作不应推进计数，base_revision 期望仍为 2，实际 %d", r)
	}

	// 当前值 expected_revision + 非事实动作 → 200 且自增（整体重构类携带时的守卫路径）
	code, _ = actJSON(t, srv, tokenB, bundleID,
		fmt.Sprintf(`{"bundle_id":%q,"action":"VOTE","cipher":%q,"expected_revision":2}`, bundleID, cipher))
	if code != http.StatusOK {
		t.Fatalf("携带当前值的动作期望 200，实际 %d", code)
	}
	if r := rev(); r != 3 {
		t.Fatalf("携带当前值的成功动作后 base_revision 期望 3，实际 %d", r)
	}

	// 事实动作携带陈旧 expected_revision → 豁免：200 且不推进计数（v0.1.3）
	code, _ = actJSON(t, srv, tokenB, bundleID,
		fmt.Sprintf(`{"bundle_id":%q,"action":"ATTACH_FACT","cipher":%q,"expected_revision":1}`, bundleID, cipher))
	if code != http.StatusOK {
		t.Fatalf("事实动作豁免期望 200，实际 %d", code)
	}
	if r := rev(); r != 3 {
		t.Fatalf("事实动作不应推进计数，base_revision 期望仍为 3，实际 %d", r)
	}
}
