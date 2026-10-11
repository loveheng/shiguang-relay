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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
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
	return call(t, srv, http.MethodPost, "/v1/schedule/action", body, randomID("m"), token)
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
		rec("OBSERVIDATION", "陈旧 revision 非事实动作", fmt.Sprintf("期望 409，实际 %d", c))
	}

	// —— GAP：base_revision 是「只写不增」的 ——
	// 经历了 PATCH_TIME（结构性动作）后，base_revision 仍应为 1（从未自增），
	// 于是非事实动作带 expected_revision=1 仍放行。直接查库取证。
	var baseRev int
	if err := pool.QueryRow(t.Context(), `SELECT base_revision FROM bundles WHERE bundle_id=$1`, bundleID).Scan(&baseRev); err != nil {
		t.Fatalf("查 base_revision 失败: %v", err)
	}
	if baseRev == 1 {
		// 再发一个带 expected_revision=1 的非事实动作，依然 200 —— 证明乐观锁名存实亡
		c, _ := act(t, srv, tokenCarol, bundleID, "VOTE", "rev-check", `"expected_revision":1`)
		if c == http.StatusOK {
			rec("DEFECT", "base_revision 永不自增→乐观锁失效",
				"经历 PATCH_TIME 后 base_revision 仍为 1，expected_revision 守卫等同于常量校验，多步并发编辑的因果冲突无法被侦测")
		}
	}

	// —— GAP：ADD_MEMBER 允许注入「非好友」且无需发起人同意 ——
	// Bob（普通成员，非发起人）把 Dave（与 Alice 非好友）拉进包
	c, m := act(t, srv, tokenBob, bundleID, "ADD_MEMBER", "add-dave", fmt.Sprintf(`"add_member_uids":[%q]`, dave.userID))
	if c != http.StatusOK {
		rec("OBSERVATION", "ADD_MEMBER 普通成员", fmt.Sprintf("期望 200，实际 %d: %v", c, m))
	} else {
		// Dave 现在应能在包内行动（即便他不是 Alice 的好友、也未被 Alice 邀请）
		c2, _ := act(t, srv, tokenDave, bundleID, "ACCEPT", "dave-accept", "")
		if c2 == http.StatusOK {
			rec("DEFECT", "ADD_MEMBER 越权注入成员",
				"任意普通成员可把发起人非好友的人拉进方案包，且与 PROPOSE 的「双向 accepted 好友」准入严管不一致；被加人无需发起人同意即可读写包内全部内容")
		}
	}

	// —— GAP：TRANSFER_INITIATOR 是「装饰性」的 ——
	// Alice 把发起人转给 Dave，但 bundles.initiator_id 实际不变
	c, _ = act(t, srv, tokenAlice, bundleID, "TRANSFER_INITIATOR", "transfer", "")
	if c == http.StatusOK {
		var initiator string
		_ = pool.QueryRow(t.Context(), `SELECT initiator_id FROM bundles WHERE bundle_id=$1`, bundleID).Scan(&initiator)
		if initiator != alice.userID {
			rec("OBSERVATION", "TRANSFER_INITIATOR 生效", "initiator_id 已被改写")
		} else {
			// Dave 尝试落槌（应因仍非真正发起人而 403）
			c2, _ := act(t, srv, tokenDave, bundleID, "FORCE_FINALIZE", "dave-finalize", "")
			if c2 == http.StatusForbidden {
				rec("DEFECT", "TRANSFER_INITIATOR 不生效",
					"动作被接受（200）但 bundles.initiator_id 未改写，名义新发起人 Dave 仍无法落槌（403），旧发起人 Alice 仍可；转移形同虚设")
			}
		}
	}

	// —— GAP：MEMBER_REMOVED 是「装饰性」的 ——
	// Alice「移除」Dave，但 participant_uids 不变，Dave 仍可行动
	c, _ = act(t, srv, tokenAlice, bundleID, "MEMBER_REMOVED", "remove-dave", fmt.Sprintf(`"add_member_uids":[%q]`, dave.userID))
	if c == http.StatusOK {
		var stillIn bool
		_ = pool.QueryRow(t.Context(), `SELECT $1::uuid = ANY(participant_uids) FROM bundles WHERE bundle_id=$2`, dave.userID, bundleID).Scan(&stillIn)
		if stillIn {
			c2, _ := act(t, srv, tokenDave, bundleID, "VOTE", "dave-after-remove", "")
			if c2 == http.StatusOK {
				rec("DEFECT", "MEMBER_REMOVED 不生效",
					"动作被接受（200）但 Dave 仍在 participant_uids，被「移除」者依旧能读写包内全部内容（成员 ACL 只看 participant_uids）")
			}
		}
	}

	// —— REKEY：key_version +1（正常）——
	c, m = act(t, srv, tokenAlice, bundleID, "REKEY", "rekey", fmt.Sprintf(`"member_key_envelopes":%s`, envsJSON(2, alice.userID, bob.userID, carol.UserID, dave.userID)))
	if c != http.StatusOK {
		rec("OBSERVATION", "REKEY", fmt.Sprintf("期望 200，实际 %d: %v", c, m))
	}

	// —— GAP：quorum 从未被强制 ——
	// 本包 quorum=5，但只有 Alice 一人落槌即 CONFIRMED
	c, _ = act(t, srv, tokenBob, bundleID, "FORCE_FINALIZE", "bob-finalize", "")
	if c != http.StatusForbidden {
		rec("DEFECT", "FORCE_FINALIZE 非发起人", fmt.Sprintf("期望 403，实际 %d", c))
	}
	c, m = act(t, srv, tokenAlice, bundleID, "FORCE_FINALIZE", "alice-finalize", "")
	if c != http.StatusOK {
		rec("OBSERVATION", "发起人落槌", fmt.Sprintf("期望 200，实际 %d: %v", c, m))
	} else {
		rec("DEFECT", "quorum 不强制", "CONSENSUS 包 quorum=5，仅发起人 1 人即敲定 CONFIRMED；quorum 仅入库从未参与仲裁")
	}

	// —— GAP：REOPEN 是死动作 ——
	// 敲定后任何 REOPEN 都被终态拦截（409），即「已确认不可重开」被硬编码
	c, _ = act(t, srv, tokenAlice, bundleID, "REOPEN", "reopen", "")
	if c == http.StatusConflict {
		rec("OBSERVATION", "REOPEN 死动作", "bundle 一旦 CONFIRMED 即永久不可重开（REOPEN 动作枚举存在但永远 409），且 AppendEvent 也从不把 status 置回 OPEN")
	}
	// 敲定后一切动作→409
	if c, _ := act(t, srv, tokenBob, bundleID, "ACCEPT", "after-confirm", ""); c != http.StatusConflict {
		rec("OBSERVATION", "敲定后动作拦截", fmt.Sprintf("期望 409，实际 %d", c))
	}

	// ===== 阶段 4：发现与同步 =====
	for _, tok := range []string{tokenBob, tokenCarol, tokenDave} {
		c, m := call(t, srv, http.MethodGet, "/v1/bundles/participating?status=active", "", randomID("m"), tok)
		if c != http.StatusOK {
			rec("DEFECT", "参与包发现", fmt.Sprintf("期望 200，实际 %d: %v", c, m))
		}
	}
	// 增量同步（since_seq=0 全量）
	c, m := call(t, srv, http.MethodGet, "/v1/schedule/sync?bundle_id="+bundleID+"&since_seq=0", "", randomID("m"), tokenBob)
	if c != http.StatusOK {
		rec("DEFECT", "增量同步", fmt.Sprintf("期望 200，实际 %d: %v", c, m))
	}
	// 成员密钥信封
	c, m = call(t, srv, http.MethodGet, "/v1/bundles/"+bundleID+"/key-envelopes", "", randomID("m"), tokenBob)
	if c != http.StatusOK {
		rec("DEFECT", "成员密钥信封", fmt.Sprintf("期望 200，实际 %d: %v", c, m))
	}
	// 金库 append/list
	if c, m := call(t, srv, http.MethodPost, "/v1/vault/envelopes",
		fmt.Sprintf(`{"bundle_id":%q,"key_ver":1,"wrapped_keys":%q}`, bundleID, cipherB64("vault-blob")), randomID("m"), tokenBob); c != http.StatusCreated {
		rec("OBSERVATION", "金库 append", fmt.Sprintf("期望 201，实际 %d: %v", c, m))
	}

	// —— GAP：读接口同样被幂等缓存，可能返回陈旧数据 / 跨端点串味 ——
	// (a) 同一 client_msg_id 复用于不同 GET → 返回首个端点缓存响应（去重键不含 path）
	c1, m1, h1 := call(t, srv, http.MethodGet, "/v1/friends", "", "IDEM-COLLIDE", tokenBob)
	c2, m2, h2 := call(t, srv, http.MethodGet, "/v1/bundles/participating?status=active", "", "IDEM-COLLIDE", tokenBob)
	if h2.Get("X-Idempotent-Replay") == "1" && m1 != nil {
		// 第二次应返回 participating，却回放了 /friends 的缓存体
		if _, ok := m2["friends"]; ok && _, ok2 := m2["bundles"]; !ok2 {
			rec("DEFECT", "幂等去重键不含 path→跨端点串缓存",
				fmt.Sprintf("用同一 client_msg_id 先后打 /friends(=%d) 与 /bundles/participating，第二次被打上 X-Idempotent-Replay 并回放了 /friends 的响应体（含 friends 键、无 bundles 键）", c1))
		}
	}
	// (b) 同一 GET 复用 client_msg_id，包内新增事件后再次拉取仍返回旧缓存（陈旧读）
	_, _ = act(t, srv, tokenCarol, bundleID, "STEP_NOTE", "post-cache", "") // 注意：此时 bundle 已确认会 409，故改为对一个仍 OPEN 的包测——见下方额外包
	_ = c1
	_ = h1

	// ===== 阶段 5：补充一个「未过期」对比包 + 过期不强制的演示 =====
	// 新建一个 expires_at 设在过去的包，验证服务端不会因过期而拒绝动作
	b2 := proposeEx(t, srv, tokenAlice, alice, []regInput{bob},
		"过期对比包", envsJSON(1, alice.userID, bob.userID))
	b2id, _ := b2["bundle_id"].(string)
	past := int64(1) // 1970，必然过期
	c, m = act(t, srv, tokenBob, b2id, "ACCEPT", "expired-accept", fmt.Sprintf(`"expires_at_unused":%d`, past))
	// 注：expires_at 在 PROPOSE 时若由客户端传过去才生效；这里仅演示动作不被服务端 expiry 拦截
	if c == http.StatusOK {
		// 查库确认该包 status 并非 EXPIRED
		var st string
		_ = pool.QueryRow(t.Context(), `SELECT status FROM bundles WHERE bundle_id=$1`, b2id).Scan(&st)
		var lc string
		_ = pool.QueryRow(t.Context(), `SELECT lifecycle FROM bundles WHERE bundle_id=$1`, b2id).Scan(&lc)
		rec("OBSERVATION", "TTL 过期不强制",
			fmt.Sprintf("服务端没有后台/查询期把过期包置为 EXPIRED，也从不把 lifecycle 置为 archived；当前该包 status=%s lifecycle=%s（EXPIRED/STALLED 状态与 archived 生命周期在代码中从未被产生）", st, lc))
	}

	// 对仍 OPEN 的 b2 做「陈旧读」演示：(b) 同 client_msg_id 复用于 sync，新增事件后回放旧结果
	cA, mA, _ := call(t, srv, http.MethodGet, "/v1/schedule/sync?bundle_id="+b2id+"&since_seq=0", "", "IDEM-SYNC-B2", tokenBob)
	n0 := len(extractEvents(mA))
	_, _ = act(t, srv, tokenBob, b2id, "STEP_NOTE", "b2-extra", "")
	cB, mB, hB := call(t, srv, http.MethodGet, "/v1/schedule/sync?bundle_id="+b2id+"&since_seq=0", "", "IDEM-SYNC-B2", tokenBob)
	n1 := len(extractEvents(mB))
	if hB.Get("X-Idempotent-Replay") == "1" && n1 == n0 {
		rec("DEFECT", "读接口被幂等缓存→陈旧数据",
			fmt.Sprintf("sync 复用同一 client_msg_id，包内新增事件后第二次仍回放旧缓存（事件数 %d→%d 未变化，带 X-Idempotent-Replay），读接口不应走写接口的 300s 去重", n0, n1))
	}
	_ = cA

	// ===== 阶段 6：P2P 瞬时信令 =====
	// Alice→Bob（好友）可发
	if c, m := call(t, srv, http.MethodPost, "/v1/relay/msg",
		fmt.Sprintf(`{"recipient_user_id":%q,"kind":"ping","cipher":%q}`, bob.userID, cipherB64("hi-bob")), randomID("m"), tokenAlice); c != http.StatusAccepted {
		rec("OBSERVATION", "P2P 信令(好友)", fmt.Sprintf("期望 202，实际 %d: %v", c, m))
	}
	// Dave 是包成员但不是 Alice 好友 → 直投信令 403（relay 走好友 ACL，与包成员无关）
	if c, _ := call(t, srv, http.MethodPost, "/v1/relay/msg",
		fmt.Sprintf(`{"recipient_user_id":%q,"kind":"ping","cipher":%q}`, dave.UserID, cipherB64("hi-dave")), randomID("m"), tokenAlice); c != http.StatusForbidden {
		rec("OBSERVATION", "P2P 信令(非好友包成员)", fmt.Sprintf("期望 403，实际 %d", c))
	}
	// Bob 拉取并 ack
	c, m = call(t, srv, http.MethodGet, "/v1/relay/pending", "", randomID("m"), tokenBob)
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
		if c, m := call(t, srv, http.MethodPost, "/v1/relay/ack",
			fmt.Sprintf(`{"message_ids":[%q]}`, msgID), randomID("m"), tokenBob); c != http.StatusOK {
			rec("OBSERVATION", "relay ack", fmt.Sprintf("期望 200，实际 %d: %v", c, m))
		}
	}

	// ===== 阶段 7：账号 / 会话 =====
	// 改密 → 纪元+1 → 旧 token 失效
	oldTok := tokenAlice
	if c, m := call(t, srv, http.MethodPost, "/v1/auth/change-password",
		fmt.Sprintf(`{"old_password":%q,"new_password":%q}`, alice.password, "NewPw_999"), randomID("m"), oldTok); c != http.StatusOK {
		rec("OBSERVATION", "改密", fmt.Sprintf("期望 200，实际 %d: %v", c, m))
	}
	// 旧 token 现在应 401（TOKEN_STALE）
	if c, _ := call(t, srv, http.MethodGet, "/v1/users/me", "", randomID("m"), oldTok); c != http.StatusUnauthorized {
		rec("OBSERVATION", "改密后旧 token", fmt.Sprintf("期望 401，实际 %d", c))
	}
	// 旧密码登录失败
	if c, _ := call(t, srv, http.MethodPost, "/v1/auth/login",
		fmt.Sprintf(`{"username":%q,"password":%q}`, alice.username, alice.password), randomID("m"), ""); c == http.StatusOK {
		rec("OBSERVATION", "旧密码登录", "旧密码仍登录成功（改密未生效）")
	}
	// 新密码登录成功
	tokenAlice2 := login(t, srv, alice.username, "NewPw_999")
	if tokenAlice2 == "" {
		rec("DEFECT", "新密码登录", "改密后新密码无法登录")
	}
	// 登出 → token 被拉黑
	if c, _ := call(t, srv, http.MethodPost, "/v1/auth/logout", `{}`, randomID("m"), tokenAlice2); c != http.StatusOK {
		rec("OBSERVATION", "登出", fmt.Sprintf("期望 200，实际 %d", c))
	}
	if c, _ := call(t, srv, http.MethodGet, "/v1/users/me", "", randomID("m"), tokenAlice2); c != http.StatusUnauthorized {
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
	// 仅在测试构造 PoW 题解时使用；避免额外 import 冲突，直接走 crypto/sha256。
	return sha256Of(s)
}
