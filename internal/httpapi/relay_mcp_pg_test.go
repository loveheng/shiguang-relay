package httpapi_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"
	relayv1 "shiguang-relay/gen/go"
	"shiguang-relay/internal/httpapi"
	"shiguang-relay/internal/store"
	"shiguang-relay/internal/wss"
)

// v0.1.8 瞬时信令在线直推（MCP over relay 轴 C 闭环的服务端半边）：
//   - 收方在线：handleRelaySend 落库后经 Hub.PushRelay 定向直推 ServerFrame.relay，
//     响应 delivered_online=true；帧携带 header（明文路由头，服务端盲转发）。
//   - 收方离线：不直推、delivered_online=false，消息留 pending（发方据 delivered_online
//     判定「手机不在线即失败」；收方重连 drain 后 ack 丢弃陈旧请求）。

func TestRelaySendDirectPushesOnlineRecipient(t *testing.T) {
	deps, _ := pgDeps(t)
	hub := wss.NewHub(deps.Issuer, deps.Bundles, wss.NoopWakePusher{})
	deps.Broadcaster = hub
	deps.WSS = hub
	deps.RelayPusher = hub
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	a := registerUser(t, srv, store.MinInitialPreKeys) // 发方（桌面桥角色）
	b := registerUser(t, srv, store.MinInitialPreKeys) // 收方（手机 app 角色）
	makeFriends(t, srv, a, b)
	tokenA := login(t, srv, a.username, a.password)

	ws := dial(t, wsURL(t, srv))
	defer ws.Close()
	if err := ws.WriteMessage(websocket.TextMessage, []byte(authJSON(t, deps.Issuer, b.userID))); err != nil {
		t.Fatal(err)
	}

	rpc := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	r := doJSON(t, srv, http.MethodPost, "/v1/relay/msg", `{
		"recipient_user_id":`+quote(b.userID)+`,"kind":"mcp",
		"cipher":`+quote(base64.StdEncoding.EncodeToString([]byte(rpc)))+`,
		"ttl_seconds":120,
		"header":{"role":"req","corr_id":"corr-1","token":"sk-mcp-token"}}`,
		randomID("m"), tokenA)
	defer r.Body.Close()
	if r.StatusCode != http.StatusAccepted {
		t.Fatalf("发单期望 202，实际 %d: %s", r.StatusCode, readAll(t, r))
	}
	var sendResp struct {
		MsgID           string `json:"msg_id"`
		DeliveredOnline bool   `json:"delivered_online"`
	}
	if err := json.NewDecoder(r.Body).Decode(&sendResp); err != nil {
		t.Fatal(err)
	}
	if sendResp.MsgID == "" || !sendResp.DeliveredOnline {
		t.Fatalf("期望在线直推送达，实际 %+v", sendResp)
	}

	// 收方读直推帧（二进制 protobuf），验 header 透传与 cipher 原样
	_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, raw, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("未收到直推帧: %v", err)
	}
	var frame relayv1.ServerFrame
	if err := proto.Unmarshal(raw, &frame); err != nil {
		t.Fatal(err)
	}
	relay := frame.GetRelay()
	if relay == nil {
		t.Fatalf("期望 ServerFrame.relay，实际 body=%T", frame.GetBody())
	}
	if relay.GetKind() != "mcp" || string(relay.GetCipher()) != rpc {
		t.Fatalf("帧内容不符: kind=%q cipher=%q", relay.GetKind(), relay.GetCipher())
	}
	if relay.GetHeader()["corr_id"] != "corr-1" || relay.GetHeader()["role"] != "req" ||
		relay.GetHeader()["token"] != "sk-mcp-token" {
		t.Fatalf("header 透传不符: %v", relay.GetHeader())
	}
}

func TestRelaySendOfflineRecipientStaysPending(t *testing.T) {
	deps, _ := pgDeps(t)
	hub := wss.NewHub(deps.Issuer, deps.Bundles, wss.NoopWakePusher{})
	deps.Broadcaster = hub
	deps.WSS = hub
	deps.RelayPusher = hub
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	c := registerUser(t, srv, store.MinInitialPreKeys)
	d := registerUser(t, srv, store.MinInitialPreKeys)
	makeFriends(t, srv, c, d)
	tokenC := login(t, srv, c.username, c.password)
	tokenD := login(t, srv, d.username, d.password)

	r := doJSON(t, srv, http.MethodPost, "/v1/relay/msg", `{
		"recipient_user_id":`+quote(d.userID)+`,"kind":"mcp",
		"cipher":`+quote(base64.StdEncoding.EncodeToString([]byte(`{"ping":true}`)))+`,
		"ttl_seconds":120,
		"header":{"role":"req","corr_id":"corr-2","token":"sk-mcp-token"}}`,
		randomID("m"), tokenC)
	defer r.Body.Close()
	if r.StatusCode != http.StatusAccepted {
		t.Fatalf("发单期望 202，实际 %d: %s", r.StatusCode, readAll(t, r))
	}
	var sendResp struct {
		DeliveredOnline bool `json:"delivered_online"`
	}
	_ = json.NewDecoder(r.Body).Decode(&sendResp)
	if sendResp.DeliveredOnline {
		t.Fatal("收方离线时不得报告在线送达")
	}

	// 离线消息落 pending，重连后可拉取（drain 后由收方 ack）
	rp := doJSON(t, srv, http.MethodGet, "/v1/relay/pending", "", randomID("m"), tokenD)
	defer rp.Body.Close()
	if rp.StatusCode != http.StatusOK {
		t.Fatalf("pending 期望 200，实际 %d", rp.StatusCode)
	}
	var pend struct {
		Messages []struct {
			Kind string `json:"kind"`
		} `json:"messages"`
	}
	if err := json.NewDecoder(rp.Body).Decode(&pend); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range pend.Messages {
		if m.Kind == "mcp" {
			found = true
		}
	}
	if !found {
		t.Fatal("离线消息未落 pending")
	}
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
