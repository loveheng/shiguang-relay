package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"shiguang-relay/internal/apierr"
)

// REST 侧重放防护的两个外层头（设计稿 §1.4：信令外层强制携带 client_msg_id + 请求时间戳）。
// WSS 侧走 proto 的 ClientFrame.client_msg_id / client_ts，两端同语义。
const (
	HeaderClientMsgID = "X-Client-Msg-Id"
	HeaderClientTs    = "X-Client-Ts"
	HeaderReplay      = "X-Idempotent-Replay"
)

// maxCaptureBytes：幂等缓存的响应体上限，对齐网关单包 256KB 硬限（§10.4）。
const maxCaptureBytes = 256 * 1024

type cachedResponse struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Body        []byte `json:"body"`
}

// Idempotency：client_msg_id 幂等去重中间件。
// 首次请求正常执行并缓存响应（SETEX 300s）；窗口内重放同 msg_id 原样回放缓存响应，不再执行业务。
type Idempotency struct {
	rdb  *redis.Client
	ttl  time.Duration
	skew time.Duration // 允许的客户端时间偏差，超出即拒（防重放旧包）
}

func NewIdempotency(rdb *redis.Client, ttl, skew time.Duration) *Idempotency {
	return &Idempotency{rdb: rdb, ttl: ttl, skew: skew}
}

func (m *Idempotency) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		msgID := r.Header.Get(HeaderClientMsgID)
		if msgID == "" {
			apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest,
				"missing X-Client-Msg-Id header", nil)
			return
		}
		tsRaw := r.Header.Get(HeaderClientTs)
		ts, err := strconv.ParseInt(tsRaw, 10, 64)
		if err != nil {
			apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest,
				"missing or invalid X-Client-Ts header", nil)
			return
		}
		if delta := time.Since(time.Unix(ts, 0)); delta > m.skew || delta < -m.skew {
			apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest,
				"client timestamp out of tolerated window", map[string]any{"skew_sec": int(m.skew.Seconds())})
			return
		}

		key := idempotencyKey(msgID)
		if raw, err := m.rdb.Get(r.Context(), key).Result(); err == nil {
			var c cachedResponse
			if err := json.Unmarshal([]byte(raw), &c); err == nil {
				w.Header().Set(HeaderReplay, "1")
				if c.ContentType != "" {
					w.Header().Set("Content-Type", c.ContentType)
				}
				w.WriteHeader(c.Status)
				_, _ = w.Write(c.Body)
				return
			}
		} else if err != redis.Nil {
			// Redis 抖动不阻断业务：降级为「不去重」继续执行（可用性优先，重放窗口内由业务幂等兜底）
			w.Header().Set("X-Idempotent-Degraded", "1")
		}

		cw := &captureWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(cw, r)

		if cw.captured {
			val, err := json.Marshal(cachedResponse{
				Status:      cw.status,
				ContentType: cw.Header().Get("Content-Type"),
				Body:        cw.body.Bytes(),
			})
			if err == nil {
				_ = m.rdb.Set(r.Context(), key, val, m.ttl).Err()
			}
		}
	})
}

type captureWriter struct {
	http.ResponseWriter
	status   int
	body     bytes.Buffer
	captured bool
	overflow bool
}

func (c *captureWriter) WriteHeader(status int) {
	if c.captured && c.status != http.StatusOK {
		return // 已写过状态码：忽略后续重复调用，避免 superfluous WriteHeader 日志与状态错乱
	}
	c.status = status
	c.captured = true
	c.ResponseWriter.WriteHeader(status)
}

func (c *captureWriter) Write(p []byte) (int, error) {
	if !c.captured {
		c.captured = true
	}
	if c.body.Len()+len(p) > maxCaptureBytes {
		c.overflow = true
		return c.ResponseWriter.Write(p)
	}
	if !c.overflow {
		c.body.Write(p)
	}
	return c.ResponseWriter.Write(p)
}
