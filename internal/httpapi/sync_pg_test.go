package httpapi_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"shiguang-relay/internal/httpapi"
	"shiguang-relay/internal/store"
)

// 发现与同步集成测试（需 RELAY_TEST_PG_DSN）——换机冷启动链路：
// participating → sync → key-envelopes / vault，外加瞬时信令 pending/ack。

func TestParticipatingAndSync(t *testing.T) {
	deps, _ := pgDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	a := registerUser(t, srv, store.MinInitialPreKeys)
	b := registerUser(t, srv, store.MinInitialPreKeys)
	c := registerUser(t, srv, store.MinInitialPreKeys) // 非成员
	makeFriends(t, srv, a, b)

	tokenA := login(t, srv, a.priv, a.userID)
	tokenB := login(t, srv, b.priv, b.userID)
	tokenC := login(t, srv, c.priv, c.userID)

	body := fmt.Sprintf(`{"action":"PROPOSE","cipher":%q,"proposal_type":"CONSENSUS",
		"participant_uids":[%q],
		"topology":{"steps":[{"step_id":"s1","required_uids":[%q,%q],"threshold":1}]},"quorum":1,
		"member_key_envelopes":[
			{"recipient_user_id":%q,"wrapped_key":%q,"key_ver":1},
			{"recipient_user_id":%q,"wrapped_key":%q,"key_ver":1}]}`,
		base64.StdEncoding.EncodeToString([]byte("propose")), b.userID,
		a.userID, b.userID,
		a.userID, base64.StdEncoding.EncodeToString([]byte("key-for-a")),
		b.userID, base64.StdEncoding.EncodeToString([]byte("key-for-b")))
	r := doJSON(t, srv, http.MethodPost, "/v1/schedule/action", body, randomID("m"), tokenA)
	defer r.Body.Close()
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("建包失败: %d %s", r.StatusCode, readAll(t, r))
	}
	var created struct {
		BundleID string `json:"bundle_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&created)
	bundleID := created.BundleID

	// 发现：A 与 B 都应看到这个包，max_seq_id=1
	for name, token := range map[string]string{"A": tokenA, "B": tokenB} {
		rp := doJSON(t, srv, http.MethodGet, "/v1/bundles/participating?status=active", "", randomID("m"), token)
		var out struct {
			Bundles []struct {
				BundleID  string `json:"bundle_id"`
				MaxSeqID  int64  `json:"max_seq_id"`
				LastAcked int64  `json:"last_acked_seq"`
			} `json:"bundles"`
		}
		_ = json.NewDecoder(rp.Body).Decode(&out)
		rp.Body.Close()
		found := false
		for _, bb := range out.Bundles {
			if bb.BundleID == bundleID {
				found = true
				if bb.MaxSeqID != 1 {
					t.Fatalf("%s 侧 max_seq_id 期望 1，实际 %d", name, bb.MaxSeqID)
				}
			}
		}
		if !found {
			t.Fatalf("%s 的 participating 未见该包（%d 条）", name, len(out.Bundles))
		}
	}

	// 增量同步：since 0 → 1 条；since 1 → 0 条
	s1 := doJSON(t, srv, http.MethodGet, "/v1/schedule/sync?bundle_id="+bundleID+"&since_seq=0", "", randomID("m"), tokenB)
	var so1 struct {
		Events    []map[string]any `json:"events"`
		LatestSeq int64            `json:"latest_seq"`
	}
	_ = json.NewDecoder(s1.Body).Decode(&so1)
	s1.Body.Close()
	if len(so1.Events) != 1 || so1.LatestSeq != 1 {
		t.Fatalf("since 0 期望 1 条/latest 1，实际 %d/%d", len(so1.Events), so1.LatestSeq)
	}
	s2 := doJSON(t, srv, http.MethodGet, "/v1/schedule/sync?bundle_id="+bundleID+"&since_seq=1", "", randomID("m"), tokenB)
	var so2 struct{ Events []map[string]any `json:"events"` }
	_ = json.NewDecoder(s2.Body).Decode(&so2)
	s2.Body.Close()
	if len(so2.Events) != 0 {
		t.Fatalf("since 1 期望 0 条，实际 %d", len(so2.Events))
	}

	// 非成员同步 → 403
	s3 := doJSON(t, srv, http.MethodGet, "/v1/schedule/sync?bundle_id="+bundleID+"&since_seq=0", "", randomID("m"), tokenC)
	s3.Body.Close()
	if s3.StatusCode != http.StatusForbidden {
		t.Fatalf("非成员 sync 期望 403，实际 %d", s3.StatusCode)
	}

	// 密钥信封：B 只拿自己的那一条
	ke := doJSON(t, srv, http.MethodGet, "/v1/bundles/"+bundleID+"/key-envelopes", "", randomID("m"), tokenB)
	var keOut struct {
		Envelopes []struct {
			KeyVer     int    `json:"key_ver"`
			WrappedKey string `json:"wrapped_key"`
		} `json:"envelopes"`
	}
	_ = json.NewDecoder(ke.Body).Decode(&keOut)
	ke.Body.Close()
	if len(keOut.Envelopes) != 1 {
		t.Fatalf("B 应只见 1 条自己的信封，实际 %d", len(keOut.Envelopes))
	}
	if got, _ := base64.StdEncoding.DecodeString(keOut.Envelopes[0].WrappedKey); string(got) != "key-for-b" {
		t.Fatalf("B 拿到的信封内容不对: %q", string(got))
	}
}

func TestVaultEnvelopesAppendOnly(t *testing.T) {
	deps, _ := pgDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	a := registerUser(t, srv, store.MinInitialPreKeys)
	tokenA := login(t, srv, a.priv, a.userID)
	bundleID := randomID("u")

	post := func(ver int, payload string) int {
		body := fmt.Sprintf(`{"bundle_id":%q,"key_ver":%d,"wrapped_keys":%q}`,
			bundleID, ver, base64.StdEncoding.EncodeToString([]byte(payload)))
		r := doJSON(t, srv, http.MethodPost, "/v1/vault/envelopes", body, randomID("m"), tokenA)
		defer r.Body.Close()
		return r.StatusCode
	}
	if post(1, "k1") != http.StatusCreated || post(2, "k2") != http.StatusCreated {
		t.Fatal("金库信封追加应 201")
	}
	// 同版本重复上传：幂等（不覆盖、不报错）
	post(1, "k1-again")

	count := func(since int) int {
		r := doJSON(t, srv, http.MethodGet, fmt.Sprintf("/v1/vault/envelopes?since_version=%d", since), "", randomID("m"), tokenA)
		defer r.Body.Close()
		var out struct{ Envelopes []map[string]any `json:"envelopes"` }
		_ = json.NewDecoder(r.Body).Decode(&out)
		return len(out.Envelopes)
	}
	if n := count(0); n != 2 {
		t.Fatalf("since 0 应返回 2 条，实际 %d", n)
	}
	if n := count(1); n != 1 {
		t.Fatalf("since 1 应返回 1 条，实际 %d", n)
	}
}

func TestRelayPendingAndAck(t *testing.T) {
	deps, _ := pgDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	a := registerUser(t, srv, store.MinInitialPreKeys)
	b := registerUser(t, srv, store.MinInitialPreKeys)
	c := registerUser(t, srv, store.MinInitialPreKeys) // 陌生人
	makeFriends(t, srv, a, b)

	tokenA := login(t, srv, a.priv, a.userID)
	tokenB := login(t, srv, b.priv, b.userID)
	login(t, srv, c.priv, c.userID) // C 仅注册，不参与信令

	// 陌生人直投 → 403（§1.7 第 2 条）
	r0 := doJSON(t, srv, http.MethodPost, "/v1/relay/msg",
		fmt.Sprintf(`{"recipient_user_id":%q,"kind":"ping","cipher":%q}`,
			c.userID, base64.StdEncoding.EncodeToString([]byte("hi"))), randomID("m"), tokenA)
	r0.Body.Close()
	if r0.StatusCode != http.StatusForbidden {
		t.Fatalf("向陌生人投信令期望 403，实际 %d", r0.StatusCode)
	}

	// 好友直投 → 202
	r1 := doJSON(t, srv, http.MethodPost, "/v1/relay/msg",
		fmt.Sprintf(`{"recipient_user_id":%q,"kind":"ping","cipher":%q,"ttl_seconds":%d}`,
			b.userID, base64.StdEncoding.EncodeToString([]byte("hello-b")), int(24*time.Hour/time.Second)),
		randomID("m"), tokenA)
	defer r1.Body.Close()
	if r1.StatusCode != http.StatusAccepted {
		t.Fatalf("投递期望 202，实际 %d", r1.StatusCode)
	}

	// B 拉取待消费 → 1 条
	p1 := doJSON(t, srv, http.MethodGet, "/v1/relay/pending", "", randomID("m"), tokenB)
	var p1Out struct {
		Messages []struct {
			MsgID  string `json:"msg_id"`
			Sender string `json:"sender_id"`
		} `json:"messages"`
	}
	_ = json.NewDecoder(p1.Body).Decode(&p1Out)
	p1.Body.Close()
	if len(p1Out.Messages) != 1 || p1Out.Messages[0].Sender != a.userID {
		t.Fatalf("B 应拉到 1 条来自 A 的信令，实际 %+v", p1Out.Messages)
	}

	// ack → 阅后即焚
	ak := doJSON(t, srv, http.MethodPost, "/v1/relay/ack",
		fmt.Sprintf(`{"message_ids":[%q]}`, p1Out.Messages[0].MsgID), randomID("m"), tokenB)
	var akOut struct{ Acked int `json:"acked"` }
	_ = json.NewDecoder(ak.Body).Decode(&akOut)
	ak.Body.Close()
	if akOut.Acked != 1 {
		t.Fatalf("ack 期望 1，实际 %d", akOut.Acked)
	}

	p2 := doJSON(t, srv, http.MethodGet, "/v1/relay/pending", "", randomID("m"), tokenB)
	var p2Out struct{ Messages []map[string]any `json:"messages"` }
	_ = json.NewDecoder(p2.Body).Decode(&p2Out)
	p2.Body.Close()
	if len(p2Out.Messages) != 0 {
		t.Fatalf("ack 后应清空，实际 %d 条", len(p2Out.Messages))
	}
}
