package httpapi_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"shiguang-relay/internal/auth"
	"shiguang-relay/internal/httpapi"
)

// 好友域集成测试（需 RELAY_TEST_PG_DSN，否则跳过）。

func signTicket(t auth.FriendshipTicket, priv ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(auth.TicketMessage(t))))
}

func inviteBody(ticket auth.FriendshipTicket, priv ed25519.PrivateKey, intro string) string {
	return fmt.Sprintf(`{"ticket":{"issuer_user_id":%q,"subject_user_id":%q,"nonce":%q,"expires_at":%d,
		"signature":%q,"enc_key_pub":%q},"encrypted_intro":%q}`,
		ticket.IssuerUserID, ticket.SubjectUserID, ticket.Nonce, ticket.ExpiresAt,
		signTicket(ticket, priv),
		base64.StdEncoding.EncodeToString(randomBytes(32)),
		intro)
}

func TestFriendInviteAcceptFlow(t *testing.T) {
	deps, _ := pgDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	// A 发起扫码，B 是 Ticket 签发人（被加者）
	a := registerUser(t, srv, 10)
	b := registerUser(t, srv, 10)
	tokenA := login(t, srv, a.priv, a.userID)
	tokenB := login(t, srv, b.priv, b.userID)

	// 未鉴权 → 401
	ticket := auth.FriendshipTicket{
		IssuerUserID:  b.userID,
		SubjectUserID: a.userID,
		Nonce:         randomID("n"),
		ExpiresAt:     time.Now().Add(time.Hour).Unix(),
	}
	r0 := doJSON(t, srv, http.MethodPost, "/v1/friends/invite",
		inviteBody(ticket, b.priv, base64.StdEncoding.EncodeToString([]byte("我是张三"))), randomID("m"), "")
	r0.Body.Close()
	if r0.StatusCode != http.StatusUnauthorized {
		t.Fatalf("未鉴权邀请期望 401，实际 %d", r0.StatusCode)
	}

	// 正常邀请 → 201 pending
	r1 := doJSON(t, srv, http.MethodPost, "/v1/friends/invite",
		inviteBody(ticket, b.priv, base64.StdEncoding.EncodeToString([]byte("我是张三"))), randomID("m"), tokenA)
	defer r1.Body.Close()
	if r1.StatusCode != http.StatusCreated {
		t.Fatalf("邀请期望 201，实际 %d: %s", r1.StatusCode, readAll(t, r1))
	}
	var created struct {
		InviteID string `json:"invite_id"`
		Status   string `json:"status"`
	}
	_ = json.NewDecoder(r1.Body).Decode(&created)
	if created.Status != "pending" || !strings.Contains(created.InviteID, a.userID) {
		t.Fatalf("邀请响应异常: %+v", created)
	}

	// 重复邀请（换 nonce）→ 409 RELATION_EXISTS
	ticket2 := ticket
	ticket2.Nonce = randomID("n")
	r2 := doJSON(t, srv, http.MethodPost, "/v1/friends/invite",
		inviteBody(ticket2, b.priv, ""), randomID("m"), tokenA)
	r2.Body.Close()
	if r2.StatusCode != http.StatusConflict {
		t.Fatalf("重复邀请期望 409，实际 %d", r2.StatusCode)
	}

	// 重放同一 nonce → 400 TICKET_NONCE_USED
	r3 := doJSON(t, srv, http.MethodPost, "/v1/friends/invite",
		inviteBody(ticket, b.priv, ""), randomID("m"), tokenA)
	r3.Body.Close()
	if r3.StatusCode != http.StatusBadRequest {
		t.Fatalf("重放 nonce 期望 400，实际 %d", r3.StatusCode)
	}

	// B（被邀方）列表可见 pending + encrypted_intro；A 侧不可见 intro
	lb := doJSON(t, srv, http.MethodGet, "/v1/friends", "", randomID("m"), tokenB)
	var lbOut struct {
		Friends []struct {
			UserID string `json:"user_id"`
			Status string `json:"status"`
			Intro  string `json:"encrypted_intro"`
		} `json:"friends"`
	}
	_ = json.NewDecoder(lb.Body).Decode(&lbOut)
	lb.Body.Close()
	if len(lbOut.Friends) != 1 || lbOut.Friends[0].Status != "pending" || lbOut.Friends[0].Intro == "" {
		t.Fatalf("B 侧应见 1 条 pending 且带 intro，实际 %+v", lbOut.Friends)
	}

	la := doJSON(t, srv, http.MethodGet, "/v1/friends", "", randomID("m"), tokenA)
	var laOut struct {
		Friends []struct {
			Status string `json:"status"`
			Intro  string `json:"encrypted_intro"`
		} `json:"friends"`
	}
	_ = json.NewDecoder(la.Body).Decode(&laOut)
	la.Body.Close()
	if len(laOut.Friends) != 1 || laOut.Friends[0].Intro != "" {
		t.Fatalf("A 侧不应看到 intro，实际 %+v", laOut.Friends)
	}

	// 发起人自己批准 → 不可达（403/404）
	r4 := doJSON(t, srv, http.MethodPost, "/v1/friends/accept",
		fmt.Sprintf(`{"invite_id":%q,"accept":true}`, created.InviteID), randomID("m"), tokenA)
	r4.Body.Close()
	if r4.StatusCode == http.StatusOK {
		t.Fatal("发起人不得批准自己发起的邀请")
	}

	// B 接受 → accepted，intro 清空
	r5 := doJSON(t, srv, http.MethodPost, "/v1/friends/accept",
		fmt.Sprintf(`{"invite_id":%q,"accept":true}`, created.InviteID), randomID("m"), tokenB)
	defer r5.Body.Close()
	if r5.StatusCode != http.StatusOK {
		t.Fatalf("接受邀请期望 200，实际 %d: %s", r5.StatusCode, readAll(t, r5))
	}
	lb2 := doJSON(t, srv, http.MethodGet, "/v1/friends", "", randomID("m"), tokenB)
	var lb2Out struct {
		Friends []struct {
			Status string `json:"status"`
			Intro  string `json:"encrypted_intro"`
		} `json:"friends"`
	}
	_ = json.NewDecoder(lb2.Body).Decode(&lb2Out)
	lb2.Body.Close()
	if len(lb2Out.Friends) != 1 || lb2Out.Friends[0].Status != "accepted" || lb2Out.Friends[0].Intro != "" {
		t.Fatalf("接受后应为 accepted 且 intro 清空，实际 %+v", lb2Out.Friends)
	}
}

func TestFriendInviteRejectsBadTickets(t *testing.T) {
	deps, _ := pgDeps(t)
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	a := registerUser(t, srv, 10)
	b := registerUser(t, srv, 10)
	c := registerUser(t, srv, 10)
	tokenA := login(t, srv, a.priv, a.userID)

	// 过期票 → 400
	expired := auth.FriendshipTicket{
		IssuerUserID:  b.userID,
		SubjectUserID: a.userID,
		Nonce:         randomID("n"),
		ExpiresAt:     time.Now().Add(-time.Minute).Unix(),
	}
	r1 := doJSON(t, srv, http.MethodPost, "/v1/friends/invite",
		inviteBody(expired, b.priv, ""), randomID("m"), tokenA)
	r1.Body.Close()
	if r1.StatusCode != http.StatusBadRequest {
		t.Fatalf("过期票期望 400，实际 %d", r1.StatusCode)
	}

	// 签名不匹配（用 C 的私钥签 B 的名片）→ 401
	forged := auth.FriendshipTicket{
		IssuerUserID:  b.userID,
		SubjectUserID: a.userID,
		Nonce:         randomID("n"),
		ExpiresAt:     time.Now().Add(time.Hour).Unix(),
	}
	r2 := doJSON(t, srv, http.MethodPost, "/v1/friends/invite",
		inviteBody(forged, c.priv, ""), randomID("m"), tokenA)
	r2.Body.Close()
	if r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("伪造签名期望 401，实际 %d", r2.StatusCode)
	}

	// subject 绑定到 C，A 提交 → 403
	wrongSubject := auth.FriendshipTicket{
		IssuerUserID:  b.userID,
		SubjectUserID: c.userID,
		Nonce:         randomID("n"),
		ExpiresAt:     time.Now().Add(time.Hour).Unix(),
	}
	r3 := doJSON(t, srv, http.MethodPost, "/v1/friends/invite",
		inviteBody(wrongSubject, b.priv, ""), randomID("m"), tokenA)
	r3.Body.Close()
	if r3.StatusCode != http.StatusForbidden {
		t.Fatalf("subject 不匹配期望 403，实际 %d", r3.StatusCode)
	}
}
