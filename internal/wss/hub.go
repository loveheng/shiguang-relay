// Package wss：WSS Hub（Phase 1.6）。
//
// 三条硬约束（协同设计 §1.4 / §10.2-3）：
//  1. 纯路径建连（wss://relay/ws）—— **token 绝不进 URL**（反代/网关 Access Log 会明文泄露凭证）；
//  2. 连接后**首帧必须是 AUTH**，3s 内未完成即掐线；
//  3. 推送按 `bundle_member_cursors.last_acked_seq` 判定落后者——只对落后者推，在线前台不再重复 Push。
//
// 帧格式：握手用 JSON 控制帧（设计稿 §1.4 明文规定 `{"action":"AUTH","token":...}`）；
// 握手之后一律 protobuf 二进制帧（`relayv1.ClientFrame` / `relayv1.ServerFrame`），避免双份编码约定。
package wss

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"
	relayv1 "shiguang-relay/gen/go"
	"shiguang-relay/internal/auth"
	"shiguang-relay/internal/store"
)

const (
	AuthTimeout   = 3 * time.Second
	WriteTimeout  = 5 * time.Second
	PongTimeout   = 60 * time.Second
	MaxFrameBytes = 256 * 1024 // §10.4 单包硬限
)

type authFrame struct {
	Action string `json:"action"`
	Token  string `json:"token"`
}

// WakePusher：离线成员的唤醒推送。Phase 1.7 实装 FCM/APNs 异步 Worker 池；
// 当前为 Noop（接口先立，避免在线路径被 push 出网阻塞——§7.1-4）。
type WakePusher interface {
	Wake(userID, bundleID string, latestSeq int64)
}

type NoopWakePusher struct{}

func (NoopWakePusher) Wake(string, string, int64) {}

type conn struct {
	ws     *websocket.Conn
	userID string
	mu     sync.Mutex
}

func (c *conn) sendBinary(b []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.ws.SetWriteDeadline(time.Now().Add(WriteTimeout))
	return c.ws.WriteMessage(websocket.BinaryMessage, b)
}

func (c *conn) sendClose(code int, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.ws.SetWriteDeadline(time.Now().Add(WriteTimeout))
	_ = c.ws.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(code, reason))
	_ = c.ws.Close()
}

// Hub：在线连接注册表 + 事件推送。实现 httpapi.Broadcaster。
type Hub struct {
	issuer  *auth.Issuer
	bundles store.BundlesStore
	pusher  WakePusher

	mu    sync.RWMutex
	conns map[string]map[*conn]struct{} // userID → 该用户的全部在线连接
}

func NewHub(issuer *auth.Issuer, bundles store.BundlesStore, pusher WakePusher) *Hub {
	if pusher == nil {
		pusher = NoopWakePusher{}
	}
	return &Hub{issuer: issuer, bundles: bundles, pusher: pusher, conns: map[string]map[*conn]struct{}{}}
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin:     func(*http.Request) bool { return true }, // 移动端无 Origin；鉴权靠首帧 AUTH 而非 Origin
}

// ServeHTTP：升级 → 首帧 AUTH（3s）→ 进入读循环。
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Warn("WS 升级失败", "err", err)
		return
	}
	ws.SetReadLimit(MaxFrameBytes)

	// 首帧 AUTH 限时
	if err := ws.SetReadDeadline(time.Now().Add(AuthTimeout)); err != nil {
		_ = ws.Close()
		return
	}
	_, raw, err := ws.ReadMessage()
	if err != nil {
		slog.Info("WS 未按时完成 AUTH，掐线", "err", err)
		_ = ws.Close()
		return
	}
	var f authFrame
	if err := json.Unmarshal(raw, &f); err != nil || f.Action != "AUTH" {
		writeJSONClose(ws, "expected AUTH frame")
		return
	}
	// 撤销语义与 REST 中间件同口径（v0.1.7）：
	//   1. 签名/有效期/类型 → VerifyClaims；
	//   2. jti 黑名单（登出 / refresh rotation 拉黑）→ 拒入；
	//   3. 改密纪元（ver 落后当前纪元）→ 拒入。
	// Hub 与 REST 共用同一 Issuer 实例（main.go 装配期 SetDeny/SetEpoch），检查随装配自动生效；
	// 黑名单/纪元存储故障时各自 fail-open，与全库限流口径一致。
	claims, err := h.issuer.VerifyClaims(f.Token, "access")
	if err != nil {
		writeJSONClose(ws, "invalid access token")
		return
	}
	if h.issuer.Revoked(r.Context(), claims.JTI) ||
		!h.issuer.CheckEpoch(r.Context(), claims.UserID, claims.Ver) {
		writeJSONClose(ws, "token revoked or stale")
		return
	}
	userID := claims.UserID

	c := &conn{ws: ws, userID: userID}
	h.register(c)
	defer h.unregister(c)

	// 鉴权通过后不再受 AUTH 计时约束，改用心跳超时
	_ = ws.SetReadDeadline(time.Now().Add(PongTimeout))
	ws.SetPongHandler(func(string) error {
		return ws.SetReadDeadline(time.Now().Add(PongTimeout))
	})

	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			return
		}
		h.handleFrame(context.Background(), c, msg)
		_ = ws.SetReadDeadline(time.Now().Add(PongTimeout))
	}
}

func writeJSONClose(ws *websocket.Conn, reason string) {
	_ = ws.SetWriteDeadline(time.Now().Add(WriteTimeout))
	_ = ws.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.ClosePolicyViolation, reason))
	_ = ws.Close()
}

// handleFrame：目前只处理 CLIENT_ACK（更新游标）；其余帧忽略（服务端不代发、不解析业务内容）。
func (h *Hub) handleFrame(ctx context.Context, c *conn, msg []byte) {
	var frame relayv1.ClientFrame
	if err := proto.Unmarshal(msg, &frame); err != nil {
		return
	}
	env := frame.GetSchedule()
	if env == nil {
		return
	}
	if env.GetAction() == relayv1.ActionType_CLIENT_ACK {
		if env.GetBundleId() == "" || env.GetSeqId() <= 0 {
			return
		}
		if err := h.bundles.UpsertCursor(ctx, env.GetBundleId(), c.userID, env.GetSeqId()); err != nil {
			slog.Warn("更新游标失败", "err", err, "user", c.userID, "bundle", env.GetBundleId())
		}
	}
}

func (h *Hub) register(c *conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.conns[c.userID] == nil {
		h.conns[c.userID] = map[*conn]struct{}{}
	}
	h.conns[c.userID][c] = struct{}{}
}

func (h *Hub) unregister(c *conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	set := h.conns[c.userID]
	if set == nil {
		return
	}
	delete(set, c)
	if len(set) == 0 {
		delete(h.conns, c.userID)
	}
}

// Publish：事件广播——在线成员直推，离线成员交给 WakePusher（§10.3-2）。
// 同步调用不阻塞业务事务太久：写超时 5s，写失败即摘连接。
func (h *Hub) Publish(bundleID string, seqID int64, action, sender string) {
	members, err := h.bundles.Participants(context.Background(), bundleID)
	if err != nil {
		slog.Warn("查询成员失败，跳过广播", "err", err, "bundle", bundleID)
		return
	}
	actionType, ok := relayv1.ActionType_value[action]
	if !ok {
		actionType = int32(relayv1.ActionType_PING)
	}

	frame := &relayv1.ServerFrame{
		SeqId: seqID,
		Body: &relayv1.ServerFrame_Schedule{
			Schedule: &relayv1.Envelope{
				BundleId:   bundleID,
				Action:     relayv1.ActionType(actionType),
				SeqId:      seqID,
				SenderHint: sender,
			},
		},
	}
	payload, err := proto.Marshal(frame)
	if err != nil {
		slog.Error("序列化 ServerFrame 失败", "err", err)
		return
	}

	for _, uid := range members {
		h.mu.RLock()
		set := h.conns[uid]
		targets := make([]*conn, 0, len(set))
		for c := range set {
			targets = append(targets, c)
		}
		h.mu.RUnlock()

		if len(targets) == 0 {
			if uid != sender {
				h.pusher.Wake(uid, bundleID, seqID)
			}
			continue
		}
		for _, c := range targets {
			if err := c.sendBinary(payload); err != nil {
				slog.Info("推送失败，摘除连接", "user", uid, "err", err)
				h.unregister(c)
			}
		}
	}
}
