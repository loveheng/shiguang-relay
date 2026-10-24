package httpapi_test

// 多人「发起活动」全流程模拟（需 RELAY_TEST_PG_DSN，否则跳过）。
//
// 目标：用 app 内已经使用的真实方法/接口，跑通「几个人发起一个活动」的完整链路，
// 并尽可能覆盖各种分支与边界；同时通过定向探针把服务端当前实现里的不足（gap）暴露出来。
//
// 本文件不编造任何接口——所有调用都走 router.go 里已挂载的真实 handler。
// 运行：
//   RELAY_TEST_PG_DSN="postgres://relay:relay@localhost:5432/relay?sslmode=disable" \
//     go test ./internal/httpapi/ -run TestSimMultiPersonActivity -count=1 -v

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"shiguang-relay/internal/httpapi"
	"shiguang-relay/internal/store"
)

// ---------------------------------------------------------------------------
// 基础工具（复用同包既有 helper：registerUser / makeFriends / login / doJSON /
// randomID；此处补少量本模拟专用工具）
// ---------------------------------------------------------------------------

type finding struct {
	sev    string // "DEFECT" | "OBSERVATION"
	title  string
	detail string
}

func qjoin(ids []string) string {
	q := make([]string, len(ids))
	for i, id := range ids {
		q[i] = fmt.Sprintf("%q", id)
	}
	return strings.Join(q, ",")
}

func cipherB64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// envsJSON：构造 member_key_envelopes（同版本幂等，服务端纯盲存储）。
func envsJSON(keyVer int, uids ...string) string {
	parts := make([]string, 0, len(uids))
	for _, u := range uids {
		parts = append(parts, fmt.Sprintf(
			`{"recipient_user_id":%q,"wrapped_key":%q,"key_ver":%d}`,
			u, base64.StdEncoding.EncodeToString(randomBytes(32)), keyVer))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// call：统一发起请求并读取 JSON 响应体（自动关闭）。
func call(t *testing.T, srv *httptest.Server, method, path, body, msgID, token string) (int, map[string]any, http.Header) {
	t.Helper()
	resp := doJSON(t, srv, method, path, body, msgID, token)
	defer resp.Body.Close()
	m := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m, resp.Header
}

// call2：call 的双值便捷包装（不关心响应头时用）。
func call2(t *testing.T, srv *httptest.Server, method, path, body, msgID, token string) (int, map[string]any) {
	t.Helper()
	c, m, _ := call(t, srv, method, path, body, msgID, token)
	return c, m
}

// proposeEx：发起活动（PROPOSE），显式带上成员密钥信封。
// members = 除发起人外的其他受邀成员（propose() 会自动把 caller 加进 participant_uids）。
func proposeEx(t *testing.T, srv *httptest.Server, token string, caller regInput, members []regInput, cipher string, envJSON string) map[string]any {
	t.Helper()
	memberUids := make([]string, 0, len(members))
	for _, m := range members {
		memberUids = append(memberUids, m.userID)
	}
	allUids := append([]string{caller.userID}, memberUids...)
	topo := fmt.Sprintf(`{"steps":[{"step_id":"s1","required_uids":[%s],"threshold":1}]}`, qjoin(allUids))
	body := fmt.Sprintf(
		`{"action":"PROPOSE","cipher":%q,"proposal_type":"CONSENSUS","participant_uids":[%s],"topology":%s,"quorum":5,"member_key_envelopes":%s}`,
		cipherB64(cipher), qjoin(memberUids), topo, envJSON)
	code, m, _ := call(t, srv, http.MethodPost, "/v1/schedule/action", body, randomID("m"), token)
	if code != http.StatusCreated {
		t.Fatalf("PROPOSE 期望 201，实际 %d: %v", code, m)
	}
	return m
}

// act：向已有 bundle 追加一个协同动作。extra 为附加 JSON 字段（如 expected_revision / add_member_uids / topology / member_key_envelopes）。
func act(t *testing.T, srv *httptest.Server, token, bundleID, action, cipher, extra string) (int, map[string]any) {
	t.Helper()
	body := fmt.Sprintf(`{"bundle_id":%q,"action":%q,"cipher":%q`, bundleID, action, cipherB64(cipher))
	if extra != "" {
		body += "," + extra
	}
	body += "}"
	code, m, _ := call(t, srv, http.MethodPost, "/v1/schedule/action", body, randomID("m"), token)
	return code, m
}

// ---------------------------------------------------------------------------
// 主模拟
// ---------------------------------------------------------------------------

func TestSimMultiPersonActivity(t *testing.T) {
	deps, pool := pgDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	var findings []finding
	rec := func(sev, title, detail string) {
		findings = append(findings, finding{sev, title, detail})
		t.Logf("[%s] %s :: %s", sev, title, detail)
	}

	// ===== 阶段 0：注册 5 个人（Alice/Bob/Carol/Dave/Eve）=====
	alice := registerUser(t, srv, store.MinInitialPreKeys)
	bob := registerUser(t, srv, store.MinInitialPreKeys)
	carol := registerUser(t, srv, store.MinInitialPreKeys)
	dave := registerUser(t, srv, store.MinInitialPreKeys)
	eve := registerUser(t, srv, store.MinInitialPreKeys)

	// —— 注册边界探针（真实接口）——
	if c, _, _ := call(t, srv, http.MethodPost, "/v1/auth/challenge", `{}`, randomID("m"), ""); c != http.StatusOK {
		t.Fatalf("challenge 期望 200，实际 %d", c)
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	// 弱密码：<8 位 → 400
	if c, m, _ := call(t, srv, http.MethodPost, "/v1/users",
		registerRawBody(t, srv, randName("u"), "short", 10, pub), randomID("m"), ""); c != http.StatusBadRequest {
		rec("OBSERVATION", "弱密码注册", fmt.Sprintf("期望 400，实际 %d（%v）", c, m))
	}
	// OPK 数量越界（3 个 < 下限 10）→ 400
	if c, _, _ := call(t, srv, http.MethodPost, "/v1/users",
		registerRawBody(t, srv, randName("u"), "Pw_12345", 3, pub), randomID("m"), ""); c != http.StatusBadRequest {
		rec("OBSERVATION", "OPK 数量越界注册", fmt.Sprintf("期望 400，实际 %d", c))
	}
	// 重复用户名 → 409
	if c, _, _ := call(t, srv, http.MethodPost, "/v1/users",
		registerRawBody(t, srv, alice.username, "Pw_12345", 10, pub), randomID("m"), ""); c != http.StatusConflict {
		rec("OBSERVATION", "重复用户名注册", fmt.Sprintf("期望 409，实际 %d", c))
	}

	tokenAlice := login(t, srv, alice.username, alice.password)
	tokenBob := login(t, srv, bob.username, bob.password)
	tokenCarol := login(t, srv, carol.username, carol.password)
	tokenDave := login(t, srv, dave.username, dave.password)
	tokenEve := login(t, srv, eve.username, eve.password)
	_ = tokenEve // Eve 仅建好友不入包（存量审计 harness 保留变量）

	// ===== 阶段 1：建好友（双通道）=====
	// Alice 扫码邀请 Bob（Ticket 通道）；Dave 扫码邀请 Eve
	makeFriends(t, srv, alice, bob)
	makeFriends(t, srv, dave, eve)

	// Alice 搜索请求 Carol（用户名搜索通道），Carol 接受
	if c, _, _ := call(t, srv, http.MethodPost, "/v1/friends/request",
		fmt.Sprintf(`{"to_user_id":%q}`, carol.userID), randomID("m"), tokenAlice); c != http.StatusCreated {
		t.Fatalf("搜索申请期望 201，实际 %d", c)
	}
	if c, _, _ := call(t, srv, http.MethodPost, "/v1/friends/accept",
		fmt.Sprintf(`{"invite_id":%q,"accept":true}`, alice.userID+":"+carol.userID), randomID("m"), tokenCarol); c != http.StatusOK {
		t.Fatalf("Carol 接受申请期望 200，实际 %d", c)
	}

	// —— 好友边界：发起人自己批准自己的邀请 → 不可达（403/404）——
	if c, _, _ := call(t, srv, http.MethodPost, "/v1/friends/accept",
		fmt.Sprintf(`{"invite_id":%q,"accept":true}`, alice.userID+":"+bob.userID), randomID("m"), tokenAlice); c == http.StatusOK {
		rec("DEFECT", "发起人可自行批准邀请", "A 自己批准 A→B 的邀请竟返回 200")
	}

	// ===== 阶段 2：发起活动（PROPOSE）=====
	bundle := proposeEx(t, srv, tokenAlice, alice, []regInput{bob, carol},
		"活动提案：周末爬山", envsJSON(1, alice.userID, bob.userID, carol.userID))
	bundleID, _ := bundle["bundle_id"].(string)
	if bundleID == "" {
		t.Fatalf("未返回 bundle_id")
	}
	if seq, _ := bundle["seq_id"].(float64); seq != 1 {
		rec("OBSERVATION", "PROPOSE seq 起点", fmt.Sprintf("期望 seq=1，实际 %v", seq))
	}

	// —— PROPOSE 边界：拉陌生人建包（Alice 与 Dave 非好友）→ 403 ——
	if c, _, _ := call(t, srv, http.MethodPost, "/v1/schedule/action",
		fmt.Sprintf(`{"action":"PROPOSE","cipher":%q,"participant_uids":[%q]}`,
			cipherB64("x"), dave.userID), randomID("m"), tokenAlice); c != http.StatusForbidden {
		rec("OBSERVATION", "拉陌生人建包", fmt.Sprintf("期望 403，实际 %d", c))
	}
	// —— PROPOSE 边界：成员超限（>16）→ 400 ——
	over := make([]string, store.MaxBundleMembers)
	for i := range over {
		over[i] = fmt.Sprintf("%q", randomID("u"))
	}
	if c, _, _ := call(t, srv, http.MethodPost, "/v1/schedule/action",
		fmt.Sprintf(`{"action":"PROPOSE","cipher":%q,"participant_uids":[%s]}`,
			cipherB64("x"), strings.Join(over, ",")), randomID("m"), tokenAlice); c != http.StatusBadRequest {
		rec("OBSERVATION", "成员超限建包", fmt.Sprintf("期望 400，实际 %d", c))
	}

	// ===== 阶段 3：协同动作（成员各显神通）=====
	// 这些动作都应成功（包内成员 ACL 放行，不要求互加好友）
	acts := []struct {
		tok    string
		who    string
		action string
	}{
		{tokenBob, "Bob", "ACCEPT"},
		{tokenCarol, "Carol", "REJECT"},
		{tokenBob, "Bob", "PATCH_TIME"},
		{tokenCarol, "Carol", "VOTE"},
		{tokenBob, "Bob", "ADD_SLOT"},
		{tokenCarol, "Carol", "NUDGE"},
		{tokenBob, "Bob", "STEP_NOTE"},
		{tokenCarol, "Carol", "BRIEFING_UPDATE"},
	}
	for _, a := range acts {
		c, m := act(t, srv, a.tok, bundleID, a.action, a.action+"-cipher", "")
		if c != http.StatusOK {
			rec("DEFECT", fmt.Sprintf("协同动作 %s(%s) 失败", a.action, a.who), fmt.Sprintf("期望 200，实际 %d: %v", c, m))
		}
	}

	// 事实三动作：绕过 base_revision 乐观锁
	for _, fa := range []string{"ATTACH_FACT", "UPDATE_FACT", "DETACH_FACT"} {
		c, _ := act(t, srv, tokenAlice, bundleID, fa, fa+"-cipher", `"expected_revision":999`)
		if c != http.StatusOK {
			rec("DEFECT", fmt.Sprintf("事实动作 %s 未绕过乐观锁", fa), fmt.Sprintf("期望 200，实际 %d", c))
		}
	}
	// 非事实动作 + 陈旧 revision → 409
	if c, _ := act(t, srv, tokenBob, bundleID, "ACCEPT", "x", `"expected_revision":999`); c != http.StatusConflict {
		rec("OBSERVATION", "陈旧 revision 非事实动作", fmt.Sprintf("期望 409，实际 %d", c))
	}

	// —— 修复验证（v0.1.10 案A拍板 2026-10-25）：base_revision 定型 bundle 级结构版本 ——
	// 每个非事实动作自增 1、事实三动作豁免；校验 opt-in（仅显式携带 expected_revision 才比对），
	// 靶向实体级冲突判定归端侧 FSM（设计 §5.4 已同步表述）。此前「只写不增→乐观锁名存实亡」缺口就此关闭。
	var baseRev int
	if err := pool.QueryRow(t.Context(), `SELECT base_revision FROM bundles WHERE bundle_id=$1`, bundleID).Scan(&baseRev); err != nil {
		t.Fatalf("查 base_revision 失败: %v", err)
	}
	if baseRev <= 1 {
		rec("DEFECT", "base_revision 未随非事实动作自增",
			fmt.Sprintf("经历 8 个非事实协同动作（PATCH_TIME/VOTE/STEP_NOTE 等）后 base_revision 仍为 %d，期望 >1（案A 每非事实动作自增）", baseRev))
	} else {
		// 陈旧 revision（=1）+ 非事实动作 → 409 STALE_REVISION：整体重构类的因果守卫活了
		if c, _ := act(t, srv, tokenCarol, bundleID, "VOTE", "rev-check", `"expected_revision":1`); c != http.StatusConflict {
			rec("DEFECT", "陈旧 base_revision 未打回",
				fmt.Sprintf("expected_revision=1（现=%d）+ 非事实动作期望 409 STALE_REVISION，实际 %d", baseRev, c))
		}
		// 不携带 expected_revision → opt-in 放行（普通平权动作永不因版本互打回，§5.4 防惊群口径）
		if c, _ := act(t, srv, tokenCarol, bundleID, "VOTE", "rev-optin", ""); c != http.StatusOK {
			rec("DEFECT", "不带 expected_revision 被误拦",
				fmt.Sprintf("opt-in 口径下不携带即放行，期望 200，实际 %d", c))
		} else {
			// 上述成功 VOTE 应恰好自增 1（事实动作与失败动作均不推进计数）
			var baseRev2 int
			_ = pool.QueryRow(t.Context(), `SELECT base_revision FROM bundles WHERE bundle_id=$1`, bundleID).Scan(&baseRev2)
			if baseRev2 != baseRev+1 {
				rec("DEFECT", "base_revision 自增步长不对",
					fmt.Sprintf("一次非事实成功动作后 %d→%d，期望恰好 +1", baseRev, baseRev2))
			}
		}
	}

	// —— 修复验证（v0.1.10）：ADD_MEMBER 发起人独占 + 双向 accepted 准入 ——
	// Bob（普通成员，非发起人）拉 Dave（与 Alice 非好友）→ 403，两道防线合一对齐 PROPOSE 准入。
	c, m := act(t, srv, tokenBob, bundleID, "ADD_MEMBER", "add-dave", fmt.Sprintf(`"add_member_uids":[%q]`, dave.userID))
	if c != http.StatusForbidden {
		rec("DEFECT", "ADD_MEMBER 越权拉人未拦", fmt.Sprintf("普通成员拉发起人非好友期望 403，实际 %d: %v", c, m))
	}
	var daveIn bool
	_ = pool.QueryRow(t.Context(), `SELECT $1::uuid = ANY(participant_uids) FROM bundles WHERE bundle_id=$2`, dave.userID, bundleID).Scan(&daveIn)
	if daveIn {
		rec("DEFECT", "ADD_MEMBER 越权注入成员", "非发起人 ADD_MEMBER 被 403 但 Dave 仍在 participant_uids")
	}

	// —— REKEY：key_version +1（正常，仅包内成员信封）——
	c, m = act(t, srv, tokenAlice, bundleID, "REKEY", "rekey", fmt.Sprintf(`"member_key_envelopes":%s`, envsJSON(2, alice.userID, bob.userID, carol.userID)))
	if c != http.StatusOK {
		rec("OBSERVATION", "REKEY", fmt.Sprintf("期望 200，实际 %d: %v", c, m))
	}

	// —— 修复验证（v0.1.10）：TRANSFER_INITIATOR 明文 transfer_to 驱动 initiator_id 改写 ——
	c, m = act(t, srv, tokenAlice, bundleID, "TRANSFER_INITIATOR", "transfer", fmt.Sprintf(`"transfer_to":%q`, bob.userID))
	if c != http.StatusOK {
		rec("DEFECT", "TRANSFER_INITIATOR 不生效", fmt.Sprintf("发起人转移期望 200，实际 %d: %v", c, m))
	} else {
		var initiator string
		_ = pool.QueryRow(t.Context(), `SELECT initiator_id::text FROM bundles WHERE bundle_id=$1`, bundleID).Scan(&initiator)
		if initiator != bob.userID {
			rec("DEFECT", "TRANSFER_INITIATOR 不生效", fmt.Sprintf("transfer_to=%s 但 initiator_id 未改写（现=%s）", bob.userID, initiator))
		} else {
			// 旧发起人失权：Alice CANCEL → 403
			c2, _ := act(t, srv, tokenAlice, bundleID, "CANCEL", "old-cancel", "")
			if c2 != http.StatusForbidden {
				rec("DEFECT", "TRANSFER_INITIATOR 后旧发起人未失权", fmt.Sprintf("旧发起人 CANCEL 期望 403，实际 %d", c2))
			}
		}
	}

	// —— 改判（设计 §4.1，2026-10-24 对账定稿）：quorum 仲裁归端侧 FSM，服务端不做票数聚合 ——
	// 新发起人 Bob 1 人落槌即 CONFIRMED 是设计内行为（服务端只做显式终态门禁）；
	// 模拟测试原期望「quorum=5 须 5 票」陈旧，本条从 DEFECT 移入 OBSERVATION 留痕。
	c, m = act(t, srv, tokenBob, bundleID, "FORCE_FINALIZE", "bob-finalize", "")
	if c != http.StatusOK {
		rec("OBSERVATION", "发起人落槌", fmt.Sprintf("期望 200，实际 %d: %v", c, m))
	} else {
		rec("OBSERVATION", "quorum 不仲裁（设计改判，非缺陷）",
			"CONSENSUS 包 quorum=5，新发起人 1 人落槌即 CONFIRMED——§4.1 对账（2026-10-24）定稿服务端不做票数聚合，quorum 判定归端侧 FSM；原模拟期望陈旧")
	}

	// —— 敲定后动作拦截（显式终态门禁）——
	if c, _ := act(t, srv, tokenBob, bundleID, "ACCEPT", "after-confirm", ""); c != http.StatusConflict {
		rec("OBSERVATION", "敲定后动作拦截", fmt.Sprintf("期望 409，实际 %d", c))
	}

	// —— 修复验证（v0.1.10）：REOPEN 终态门禁白名单第三动作（CONSENSUS 包内平权 §4.4）——
	// 敲定后 REOPEN 不再 409：放行且显式置回 STALLED，普通动作重新可入。
	c, m = act(t, srv, tokenAlice, bundleID, "REOPEN", "reopen", "")
	if c != http.StatusOK {
		rec("DEFECT", "REOPEN 终态门禁缺口未实装", fmt.Sprintf("CONSENSUS 成员敲定后 REOPEN 期望 200，实际 %d: %v", c, m))
	} else if m["status"] != "STALLED" {
		rec("DEFECT", "REOPEN 后状态未置回", fmt.Sprintf("期望 status=STALLED，实际 %v", m["status"]))
	} else if c2, _ := act(t, srv, tokenBob, bundleID, "ACCEPT", "after-reopen", ""); c2 != http.StatusOK {
		rec("DEFECT", "REOPEN 后普通动作不可入", fmt.Sprintf("重开后 ACCEPT 期望 200，实际 %d", c2))
	}

	// ===== 阶段 4：发现与同步 =====
	for _, tok := range []string{tokenBob, tokenCarol, tokenDave} {
		c, m := call2(t, srv, http.MethodGet, "/v1/bundles/participating?status=active", "", randomID("m"), tok)
		if c != http.StatusOK {
			rec("DEFECT", "参与包发现", fmt.Sprintf("期望 200，实际 %d: %v", c, m))
		}
	}
	// 增量同步（since_seq=0 全量）
	c, m = call2(t, srv, http.MethodGet, "/v1/schedule/sync?bundle_id="+bundleID+"&since_seq=0", "", randomID("m"), tokenBob)
	if c != http.StatusOK {
		rec("DEFECT", "增量同步", fmt.Sprintf("期望 200，实际 %d: %v", c, m))
	}
	// 成员密钥信封
	c, m = call2(t, srv, http.MethodGet, "/v1/bundles/"+bundleID+"/key-envelopes", "", randomID("m"), tokenBob)
	if c != http.StatusOK {
		rec("DEFECT", "成员密钥信封", fmt.Sprintf("期望 200，实际 %d: %v", c, m))
	}
	// 金库 append/list
	if c, m := call2(t, srv, http.MethodPost, "/v1/vault/envelopes",
		fmt.Sprintf(`{"bundle_id":%q,"key_ver":1,"wrapped_keys":%q}`, bundleID, cipherB64("vault-blob")), randomID("m"), tokenBob); c != http.StatusCreated {
		rec("OBSERVATION", "金库 append", fmt.Sprintf("期望 201，实际 %d: %v", c, m))
	}

	// —— 修复验证（v0.1.10）：幂等去重键含 method+path + GET 直通 ——
	// (a) 跨端点：同一 client_msg_id 先打写端点 A（relay 发信）再打写端点 B（schedule 动作），
	//     不得回放 A 的缓存体（键=idem:{method}:{path}:{client_msg_id}）。
	c1, _, _ := call(t, srv, http.MethodPost, "/v1/relay/msg",
		fmt.Sprintf(`{"recipient_user_id":%q,"kind":"ping","cipher":%q}`, bob.userID, cipherB64("idem-collide")),
		"IDEM-COLLIDE", tokenAlice)
	if c1 != http.StatusAccepted {
		rec("OBSERVATION", "幂等跨端点前置", fmt.Sprintf("relay 发信期望 202，实际 %d", c1))
	} else {
		c2, m2, h2 := call(t, srv, http.MethodPost, "/v1/schedule/action",
			fmt.Sprintf(`{"bundle_id":%q,"action":"ACCEPT","cipher":%q}`, bundleID, cipherB64("idem-accept")),
			"IDEM-COLLIDE", tokenBob)
		if h2.Get("X-Idempotent-Replay") == "1" || m2["bundle_id"] == nil {
			rec("DEFECT", "幂等去重键不含 path→跨端点串缓存",
				fmt.Sprintf("同 client_msg_id 先后打 /relay/msg(=%d) 与 /schedule/action(=%d)，第二次%s（含 bundle_id 键=%v）",
					c1, c2, map[bool]string{true: "被回放缓存"}[h2.Get("X-Idempotent-Replay") == "1"], m2["bundle_id"] != nil))
		}
	}
	// (b) GET 直通：同一 client_msg_id 复用于 sync，包内新增事件后二次拉取必须拿到新事件
	//     （读接口不走写缓存，杜绝 300s 陈旧回放）。
	_, mA, _ := call(t, srv, http.MethodGet, "/v1/schedule/sync?bundle_id="+bundleID+"&since_seq=0", "", "IDEM-SYNC-MAIN", tokenBob)
	n0 := len(extractEvents(mA))
	_, _ = act(t, srv, tokenCarol, bundleID, "STEP_NOTE", "post-cache", "")
	_, mB, hB := call(t, srv, http.MethodGet, "/v1/schedule/sync?bundle_id="+bundleID+"&since_seq=0", "", "IDEM-SYNC-MAIN", tokenBob)
	n1 := len(extractEvents(mB))
	if hB.Get("X-Idempotent-Replay") == "1" || n1 <= n0 {
		rec("DEFECT", "读接口被幂等缓存→陈旧数据",
			fmt.Sprintf("sync 复用同一 client_msg_id，包内新增事件后第二次未拿到增量（事件数 %d→%d，replay=%q），读接口不应走写接口的 300s 去重", n0, n1, hB.Get("X-Idempotent-Replay")))
	}

	// ===== 阶段 5：补充一个「未过期」对比包 + TTL/MEMBER_REMOVED 探针 =====
	// 新建一个 expires_at 设在过去的包，验证服务端不会因过期而拒绝动作
	b2 := proposeEx(t, srv, tokenAlice, alice, []regInput{bob},
		"过期对比包", envsJSON(1, alice.userID, bob.userID))
	b2id, _ := b2["bundle_id"].(string)
	past := int64(1) // 1970，必然过期
	c, m = act(t, srv, tokenBob, b2id, "ACCEPT", "expired-accept", fmt.Sprintf(`"expires_at":%d`, past))
	// 注：expires_at 仅在 PROPOSE 时由客户端传入生效；这里仅演示动作不被服务端 expiry 拦截
	if c == http.StatusOK {
		// 查库确认该包 status 并非 EXPIRED
		var st string
		_ = pool.QueryRow(t.Context(), `SELECT status FROM bundles WHERE bundle_id=$1`, b2id).Scan(&st)
		var lc string
		_ = pool.QueryRow(t.Context(), `SELECT lifecycle FROM bundles WHERE bundle_id=$1`, b2id).Scan(&lc)
		rec("OBSERVATION", "TTL 过期不强制",
			fmt.Sprintf("服务端没有后台/查询期把过期包置为 EXPIRED，也从不把 lifecycle 置为 archived；当前该包 status=%s lifecycle=%s（EXPIRED/STALLED 状态与 archived 生命周期在代码中从未被产生）", st, lc))
	}

	// —— 修复验证（v0.1.10）：MEMBER_REMOVED 明文 remove_member_uids 驱动移出 participant_uids ——
	// 发起人 Alice 把 Bob 移出 b2 → 200 且即刻失去包内 ACL（全语义 REKEY 连带挂账 §5.3.1）。
	c, m = act(t, srv, tokenAlice, b2id, "MEMBER_REMOVED", "remove-bob", fmt.Sprintf(`"remove_member_uids":[%q]`, bob.userID))
	if c != http.StatusOK {
		rec("DEFECT", "MEMBER_REMOVED 不生效", fmt.Sprintf("发起人移除成员期望 200，实际 %d: %v", c, m))
	} else {
		var stillIn bool
		_ = pool.QueryRow(t.Context(), `SELECT $1::uuid = ANY(participant_uids) FROM bundles WHERE bundle_id=$2`, bob.userID, b2id).Scan(&stillIn)
		if stillIn {
			rec("DEFECT", "MEMBER_REMOVED 不生效", "remove_member_uids 已传但被移除者仍在 participant_uids（成员 ACL 只看 participant_uids）")
		} else if c2, _ := act(t, srv, tokenBob, b2id, "VOTE", "bob-after-remove", ""); c2 != http.StatusForbidden {
			rec("DEFECT", "MEMBER_REMOVED 不生效", fmt.Sprintf("被移除者后续动作期望 403，实际 %d", c2))
		}
	}

	// ===== 阶段 6：P2P 瞬时信令 =====
	// Alice→Bob（好友）可发
	if c, m := call2(t, srv, http.MethodPost, "/v1/relay/msg",
		fmt.Sprintf(`{"recipient_user_id":%q,"kind":"ping","cipher":%q}`, bob.userID, cipherB64("hi-bob")), randomID("m"), tokenAlice); c != http.StatusAccepted {
		rec("OBSERVATION", "P2P 信令(好友)", fmt.Sprintf("期望 202，实际 %d: %v", c, m))
	}
	// Dave 与 Alice 非好友（v0.1.10 后不再被越权拉入包）→ 直投信令 403（relay 走好友 ACL，与包成员无关）
	if c, _ := call2(t, srv, http.MethodPost, "/v1/relay/msg",
		fmt.Sprintf(`{"recipient_user_id":%q,"kind":"ping","cipher":%q}`, dave.userID, cipherB64("hi-dave")), randomID("m"), tokenAlice); c != http.StatusForbidden {
		rec("OBSERVATION", "P2P 信令(非好友)", fmt.Sprintf("期望 403，实际 %d", c))
	}
	// Bob 拉取并 ack
	c, m = call2(t, srv, http.MethodGet, "/v1/relay/pending", "", randomID("m"), tokenBob)
	if c != http.StatusOK {
		rec("OBSERVATION", "relay pending", fmt.Sprintf("期望 200，实际 %d: %v", c, m))
	}
	var msgID string
	if arr, ok := m["messages"].([]any); ok && len(arr) > 0 {
		if mm, ok := arr[0].(map[string]any); ok {
			msgID, _ = mm["msg_id"].(string)
		}
	}
	if msgID != "" {
		if c, m := call2(t, srv, http.MethodPost, "/v1/relay/ack",
			fmt.Sprintf(`{"message_ids":[%q]}`, msgID), randomID("m"), tokenBob); c != http.StatusOK {
			rec("OBSERVATION", "relay ack", fmt.Sprintf("期望 200，实际 %d: %v", c, m))
		}
	}

	// ===== 阶段 7：账号 / 会话 =====
	// 改密 → 纪元+1 → 旧 token 失效
	oldTok := tokenAlice
	if c, m := call2(t, srv, http.MethodPost, "/v1/auth/change-password",
		fmt.Sprintf(`{"old_password":%q,"new_password":%q}`, alice.password, "NewPw_999"), randomID("m"), oldTok); c != http.StatusOK {
		rec("OBSERVATION", "改密", fmt.Sprintf("期望 200，实际 %d: %v", c, m))
	}
	// 旧 token 现在应 401（TOKEN_STALE）
	if c, _ := call2(t, srv, http.MethodGet, "/v1/users/me", "", randomID("m"), oldTok); c != http.StatusUnauthorized {
		rec("OBSERVATION", "改密后旧 token", fmt.Sprintf("期望 401，实际 %d", c))
	}
	// 旧密码登录失败
	if c, _ := call2(t, srv, http.MethodPost, "/v1/auth/login",
		fmt.Sprintf(`{"username":%q,"password":%q}`, alice.username, alice.password), randomID("m"), ""); c == http.StatusOK {
		rec("OBSERVATION", "旧密码登录", "旧密码仍登录成功（改密未生效）")
	}
	// 新密码登录成功
	tokenAlice2 := login(t, srv, alice.username, "NewPw_999")
	if tokenAlice2 == "" {
		rec("DEFECT", "新密码登录", "改密后新密码无法登录")
	}
	// 登出 → token 被拉黑
	if c, _ := call2(t, srv, http.MethodPost, "/v1/auth/logout", `{}`, randomID("m"), tokenAlice2); c != http.StatusOK {
		rec("OBSERVATION", "登出", fmt.Sprintf("期望 200，实际 %d", c))
	}
	if c, _ := call2(t, srv, http.MethodGet, "/v1/users/me", "", randomID("m"), tokenAlice2); c != http.StatusUnauthorized {
		rec("DEFECT", "登出后 token 复用", fmt.Sprintf("登出后旧 token 仍可用，期望 401，实际 %d", c))
	}

	// ===== 汇总 =====
	defects, obs := 0, 0
	for _, f := range findings {
		if f.sev == "DEFECT" {
			defects++
		} else {
			obs++
		}
	}
	t.Logf("==================== 模拟发现汇总 ====================")
	t.Logf("DEFECT(明确缺陷): %d | OBSERVATION(设计性/待确认): %d", defects, obs)
	if defects > 0 {
		t.Errorf("模拟共发现 %d 处明确缺陷，详见上方 [DEFECT] 日志", defects)
	}
}

// extractEvents：从 sync 响应里取 events 数组长度（兼容缺字段）。
func extractEvents(m map[string]any) []any {
	if arr, ok := m["events"].([]any); ok {
		return arr
	}
	return nil
}

// registerRawBody：复用 registerRaw 的构造逻辑，但直接返回 body 字符串（便于在探针里直接发）。
func registerRawBody(t *testing.T, srv *httptest.Server, username, password string, opks int, identityPub ed25519.PublicKey) string {
	t.Helper()
	resp := doJSON(t, srv, http.MethodPost, "/v1/auth/challenge", `{}`, randomID("m"), "")
	var ch struct {
		Nonce         string `json:"nonce"`
		PowChallenge  string `json:"pow_challenge"`
		PowDifficulty int    `json:"pow_difficulty"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&ch)
	resp.Body.Close()

	var solution string
	for i := 0; ; i++ {
		s := fmt.Sprintf("%d-%s", i, ch.Nonce)
		if authVerifyPoW(ch.PowChallenge, s, ch.PowDifficulty) {
			solution = s
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
	return fmt.Sprintf(`{
		"username":%q,"password":%q,
		"identity_key_pub":%q,"signed_prekey_pub":%q,"signed_prekey_sig":%q,
		"nonce":%q,"pow_solution":%q,
		"one_time_prekeys":[%s]}`,
		username, password,
		base64.StdEncoding.EncodeToString(identityPub),
		base64.StdEncoding.EncodeToString(randomBytes(32)),
		base64.StdEncoding.EncodeToString(randomBytes(64)),
		ch.Nonce, solution, strings.Join(opkJSON, ","))
}

// authVerifyPoW：本地复刻 auth.VerifyPoW（同包不可见，故在此小复制一份用于模拟构造题解）。
func authVerifyPoW(challenge, solution string, difficulty int) bool {
	if difficulty <= 0 {
		return true
	}
	h := sha256Sum(challenge + ":" + solution)
	zeroBits := 0
	for _, b := range h {
		for mask := byte(0x80); mask != 0; mask >>= 1 {
			if b&mask == 0 {
				zeroBits++
			} else {
				return zeroBits >= difficulty
			}
		}
	}
	return zeroBits >= difficulty
}

func sha256Sum(s string) []byte {
	// 仅在测试构造 PoW 题解时使用。
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}
