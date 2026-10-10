package httpapi_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"
	relayv1 "shiguang-relay/gen/go"
	"shiguang-relay/internal/auth"
	"shiguang-relay/internal/httpapi"
	"shiguang-relay/internal/store"
	"shiguang-relay/internal/wss"
)

// WSS Hub 集成测试（需 RELAY_TEST_PG_DSN）。

func wsURL(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	return "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
}

func dial(t *testing.T, url string) *websocket.Conn {
	t.Helper()
	c, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func authJSON(t *testing.T, iss *auth.Issuer, userID string) string {
	t.Helper()
	pair, err := iss.Issue(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(`{"action":"AUTH","token":%q}`, pair.AccessToken)
}

// TestWSSAuthRejectsRevokedAndStale：撤销语义与 REST 同口径——
// jti 已拉黑（登出）或纪元落后（改密）的 access token 首帧 AUTH 即被拒。
func TestWSSAuthRejectsRevokedAndStale(t *testing.T) {
	deps, _ := pgDeps(t)
	hub := wss.NewHub(deps.Issuer, deps.Bundles, wss.NoopWakePusher{})
	deps.Broadcaster = hub
	deps.WSS = hub
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	a := registerUser(t, srv, store.MinInitialPreKeys)
	ctx := context.Background()

	// 场景 1：jti 拉黑（等价登出）→ AUTH 拒入
	pair1, err := deps.Issuer.Issue(ctx, a.userID)
	if err != nil {
		t.Fatal(err)
	}
	claims1, err := deps.Issuer.VerifyClaims(pair1.AccessToken, "access")
	if err != nil {
		t.Fatal(err)
	}
	if err := deps.Deny.Add(ctx, claims1.JTI, time.Minute); err != nil {
		t.Fatal(err)
	}
	assertWSSAuthRejected(t, srv, pair1.AccessToken)

	// 场景 2：纪元落后（等价改密踢会话）→ AUTH 拒入。
	// pair2 在 Bump 前签发（ver=0、干净 jti）——Bump 后被拒只能来自纪元检查，与黑名单隔离。
	pair2, err := deps.Issuer.Issue(ctx, a.userID)
	if err != nil {
		t.Fatal(err)
	}
	if err := deps.Epochs.Bump(ctx, a.userID); err != nil {
		t.Fatal(err)
	}
	assertWSSAuthRejected(t, srv, pair2.AccessToken)
}

// assertWSSAuthRejected：发送 AUTH 后服务端应发 Close 帧并断开（读出错即视为拒入）。
func assertWSSAuthRejected(t *testing.T, srv *httptest.Server, token string) {
	t.Helper()
	c := dial(t, wsURL(t, srv))
	defer c.Close()
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := c.WriteMessage(websocket.TextMessage,
		[]byte(fmt.Sprintf(`{"action":"AUTH","token":%q}`, token))); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := c.ReadMessage(); err == nil {
		t.Fatal("被撤销/过期的 token 不应完成 WSS AUTH")
	}
}

func TestWSSAuthAndBroadcast(t *testing.T) {
	deps, _ := pgDeps(t)
	issuer := deps.Issuer
	hub := wss.NewHub(issuer, deps.Bundles, wss.NoopWakePusher{})
	deps.Broadcaster = hub
	deps.WSS = hub

	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	a := registerUser(t, srv, store.MinInitialPreKeys)
	b := registerUser(t, srv, store.MinInitialPreKeys)
	makeFriends(t, srv, a, b)
	tokenA := login(t, srv, a.username, a.password)

	res := proposeBundle(t, srv, tokenA, []string{b.userID}, base64.StdEncoding.EncodeToString([]byte("c")))
	bundleID, _ := res["bundle_id"].(string)

	// A 上线并完成首帧 AUTH
	c := dial(t, wsURL(t, srv))
	defer c.Close()
	if err := c.WriteMessage(websocket.TextMessage, []byte(authJSON(t, issuer, a.userID))); err != nil {
		t.Fatal(err)
	}

	// 广播一条事件（模拟 action 落库后的推送）
	time.Sleep(100 * time.Millisecond) // 等服务端完成注册
	hub.Publish(bundleID, 7, "ACCEPT", b.userID)

	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	typ, msg, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("未收到推送: %v", err)
	}
	if typ != websocket.BinaryMessage {
		t.Fatalf("期望二进制 protobuf 帧，实际类型 %d", typ)
	}
	var frame relayv1.ServerFrame
	if err := proto.Unmarshal(msg, &frame); err != nil {
		t.Fatalf("ServerFrame 解码失败: %v", err)
	}
	if frame.GetSeqId() != 7 {
		t.Fatalf("seq 期望 7，实际 %d", frame.GetSeqId())
	}
	env := frame.GetSchedule()
	if env == nil || env.GetBundleId() != bundleID {
		t.Fatalf("推送的 bundle_id 不符: %+v", env)
	}
	if env.GetAction() != relayv1.ActionType_ACCEPT {
		t.Fatalf("动作枚举应为 ACCEPT，实际 %v", env.GetAction())
	}
}

func TestWSSClientAckUpdatesCursor(t *testing.T) {
	deps, pool := pgDeps(t)
	issuer := deps.Issuer
	hub := wss.NewHub(issuer, deps.Bundles, wss.NoopWakePusher{})
	deps.Broadcaster = hub
	deps.WSS = hub

	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	a := registerUser(t, srv, store.MinInitialPreKeys)
	b := registerUser(t, srv, store.MinInitialPreKeys)
	makeFriends(t, srv, a, b)
	tokenA := login(t, srv, a.username, a.password)
	res := proposeBundle(t, srv, tokenA, []string{b.userID}, base64.StdEncoding.EncodeToString([]byte("c")))
	bundleID, _ := res["bundle_id"].(string)

	c := dial(t, wsURL(t, srv))
	defer c.Close()
	if err := c.WriteMessage(websocket.TextMessage, []byte(authJSON(t, issuer, a.userID))); err != nil {
		t.Fatal(err)
	}

	frame := &relayv1.ClientFrame{
		ClientMsgId: "ack-1",
		ClientTs:    time.Now().Unix(),
		Body: &relayv1.ClientFrame_Schedule{
			Schedule: &relayv1.Envelope{
				BundleId: bundleID,
				Action:   relayv1.ActionType_CLIENT_ACK,
				SeqId:    5,
			},
		},
	}
	payload, err := proto.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WriteMessage(websocket.BinaryMessage, payload); err != nil {
		t.Fatal(err)
	}

	var seq int64
	for i := 0; i < 40; i++ {
		_ = pool.QueryRow(context.Background(),
			`SELECT COALESCE(last_acked_seq,0) FROM bundle_member_cursors WHERE bundle_id = $1 AND user_id = $2`,
			bundleID, a.userID).Scan(&seq)
		if seq == 5 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if seq != 5 {
		t.Fatalf("CLIENT_ACK 应把游标落到 5，实际 %d", seq)
	}
}

func TestWSSRejectsUnauthenticated(t *testing.T) {
	deps, _ := pgDeps(t)
	hub := wss.NewHub(deps.Issuer, deps.Bundles, wss.NoopWakePusher{})
	deps.WSS = hub
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	// 1) 不发送任何帧 → 3s 超时掐线
	c1 := dial(t, wsURL(t, srv))
	defer c1.Close()
	_ = c1.SetReadDeadline(time.Now().Add(8 * time.Second))
	if _, _, err := c1.ReadMessage(); err == nil {
		t.Fatal("未 AUTH 的连接应被掐线（读应报错）")
	}

	// 2) 非法 token → 立即关闭
	c2 := dial(t, wsURL(t, srv))
	defer c2.Close()
	if err := c2.WriteMessage(websocket.TextMessage, []byte(`{"action":"AUTH","token":"garbage"}`)); err != nil {
		t.Fatal(err)
	}
	_ = c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := c2.ReadMessage(); err == nil {
		t.Fatal("非法 token 应被关闭")
	}
}
