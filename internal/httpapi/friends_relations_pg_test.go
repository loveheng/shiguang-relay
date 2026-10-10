package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"shiguang-relay/internal/httpapi"
	"shiguang-relay/internal/store"
)

// 好友关系对称化（需 RELAY_TEST_PG_DSN）：删除好友 / 主动拉黑 / blocked 双向静默 / 解拉黑出路。

// requestFriend：A 以 Bearer 直发申请（搜索路径）。
func requestFriend(t *testing.T, srv *httptest.Server, token, toUserID string) *http.Response {
	t.Helper()
	return doJSON(t, srv, http.MethodPost, "/v1/friends/request",
		fmt.Sprintf(`{"to_user_id":%q}`, toUserID), randomID("m"), token)
}

// TestRemoveFriendAndReinvite：申请→接受→删除→列表清空→可重新申请。
func TestRemoveFriendAndReinvite(t *testing.T) {
	deps, _ := pgDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	a := registerUser(t, srv, store.MinInitialPreKeys)
	b := registerUser(t, srv, store.MinInitialPreKeys)
	tokenA := login(t, srv, a.username, a.password)
	tokenB := login(t, srv, b.username, b.password)

	r1 := requestFriend(t, srv, tokenA, b.userID)
	r1.Body.Close()
	if r1.StatusCode != http.StatusCreated {
		t.Fatalf("申请期望 201，实际 %d", r1.StatusCode)
	}
	r2 := doJSON(t, srv, http.MethodPost, "/v1/friends/accept",
		fmt.Sprintf(`{"invite_id":%q,"accept":true}`, a.userID+":"+b.userID), randomID("m"), tokenB)
	r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("接受期望 200，实际 %d", r2.StatusCode)
	}

	// A 删除好友 → 200
	r3 := doJSON(t, srv, http.MethodDelete, "/v1/friends/"+b.userID, "", randomID("m"), tokenA)
	r3.Body.Close()
	if r3.StatusCode != http.StatusOK {
		t.Fatalf("删除好友期望 200，实际 %d", r3.StatusCode)
	}

	// 双方列表清空
	for _, tok := range []string{tokenA, tokenB} {
		l := doJSON(t, srv, http.MethodGet, "/v1/friends", "", randomID("m"), tok)
		var out struct {
			Friends []map[string]any `json:"friends"`
		}
		_ = json.NewDecoder(l.Body).Decode(&out)
		l.Body.Close()
		if len(out.Friends) != 0 {
			t.Fatalf("删除后列表应清空，实际 %+v", out.Friends)
		}
	}

	// 删除后可重新申请（此前缺口：409 死锁）
	r4 := requestFriend(t, srv, tokenA, b.userID)
	defer r4.Body.Close()
	if r4.StatusCode != http.StatusCreated {
		t.Fatalf("删除后重新申请期望 201，实际 %d", r4.StatusCode)
	}

	// 无关系再删 → 404（幽灵 user：无任何行可删）
	r5 := doJSON(t, srv, http.MethodDelete, "/v1/friends/"+randomID("ghost"), "", randomID("m"), tokenB)
	r5.Body.Close()
	if r5.StatusCode != http.StatusNotFound {
		t.Fatalf("删除不存在关系期望 404，实际 %d", r5.StatusCode)
	}
}

// TestBlockSilencesBothDirections：B 拉黑 A（无既有关系）→ A/B 双向申请均静默 409；解拉黑后可重申。
func TestBlockSilencesBothDirections(t *testing.T) {
	deps, _ := pgDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	a := registerUser(t, srv, store.MinInitialPreKeys)
	b := registerUser(t, srv, store.MinInitialPreKeys)
	tokenA := login(t, srv, a.username, a.password)
	tokenB := login(t, srv, b.username, b.password)

	// B 主动拉黑 A（无既有关系）→ 200
	r0 := doJSON(t, srv, http.MethodPost, "/v1/friends/"+a.userID+"/block", "", randomID("m"), tokenB)
	r0.Body.Close()
	if r0.StatusCode != http.StatusOK {
		t.Fatalf("主动拉黑期望 200，实际 %d", r0.StatusCode)
	}

	// 被拉黑方 A 申请 B → 409（静默，不告知被拉黑）
	r1 := requestFriend(t, srv, tokenA, b.userID)
	r1.Body.Close()
	if r1.StatusCode != http.StatusConflict {
		t.Fatalf("被拉黑方申请期望 409，实际 %d", r1.StatusCode)
	}

	// 反向：拉黑方自己 B → A 的「新关系」申请同样 409（行方向已定）
	r2 := requestFriend(t, srv, tokenB, a.userID)
	r2.Body.Close()
	if r2.StatusCode != http.StatusConflict {
		t.Fatalf("拉黑方申请期望 409，实际 %d", r2.StatusCode)
	}

	// pending → 拉黑转换：C 申请 D，D 拉黑 C → C 再申请仍 409
	c := registerUser(t, srv, store.MinInitialPreKeys)
	d := registerUser(t, srv, store.MinInitialPreKeys)
	tokenC := login(t, srv, c.username, c.password)
	tokenD := login(t, srv, d.username, d.password)
	r3 := requestFriend(t, srv, tokenC, d.userID)
	r3.Body.Close()
	if r3.StatusCode != http.StatusCreated {
		t.Fatalf("C 申请 D 期望 201，实际 %d", r3.StatusCode)
	}
	r4 := doJSON(t, srv, http.MethodPost, "/v1/friends/"+c.userID+"/block", "", randomID("m"), tokenD)
	r4.Body.Close()
	if r4.StatusCode != http.StatusOK {
		t.Fatalf("pending 转拉黑期望 200，实际 %d", r4.StatusCode)
	}
	r5 := requestFriend(t, srv, tokenC, d.userID)
	r5.Body.Close()
	if r5.StatusCode != http.StatusConflict {
		t.Fatalf("pending 被拉黑后申请期望 409，实际 %d", r5.StatusCode)
	}

	// 解拉黑（删除 blocked 行）→ 重新申请放行
	r6 := doJSON(t, srv, http.MethodDelete, "/v1/friends/"+a.userID, "", randomID("m"), tokenB)
	r6.Body.Close()
	if r6.StatusCode != http.StatusOK {
		t.Fatalf("解拉黑期望 200，实际 %d", r6.StatusCode)
	}
	r7 := requestFriend(t, srv, tokenA, b.userID)
	defer r7.Body.Close()
	if r7.StatusCode != http.StatusCreated {
		t.Fatalf("解拉黑后重新申请期望 201，实际 %d", r7.StatusCode)
	}
}
