package auth

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// 幂等中间件作用域回归（v0.1.10 缺陷修复）：
//  1. 去重键含 method+path——同 client_msg_id 打不同端点不得串缓存；
//  2. GET 直通——读接口不缓存（300s 回放对读是陈旧读毒药），去重只为写重放防护。
func TestIdempotencyScopingMethodAndPath(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	m := NewIdempotency(rdb, 5*time.Minute, 5*time.Minute)

	hit := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit++
		_, _ = w.Write([]byte(r.URL.Path))
	})
	h := m.Wrap(next)
	now := time.Now().Unix()
	do := func(method, path, msgID string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set(HeaderClientMsgID, msgID)
		req.Header.Set(HeaderClientTs, strconv.FormatInt(now, 10))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// 1) 同 path 同 msg_id 的 POST → 第二次回放（去重仍生效）
	hit = 0
	r1 := do(http.MethodPost, "/v1/x", "same-id")
	r2 := do(http.MethodPost, "/v1/x", "same-id")
	if hit != 1 {
		t.Fatalf("同 path 同 msg_id 应执行一次业务，实际 %d", hit)
	}
	if r2.Header().Get(HeaderReplay) != "1" || r2.Body.String() != r1.Body.String() {
		t.Fatal("同 path 重放应命中缓存")
	}

	// 2) 同 msg_id 换 path → 不得回放（键含 path）
	hit = 0
	r3 := do(http.MethodPost, "/v1/y", "same-id")
	if hit != 1 || r3.Header().Get(HeaderReplay) == "1" || r3.Body.String() != "/v1/y" {
		t.Fatalf("跨端点同 msg_id 不应串缓存：hit=%d replay=%q body=%q", hit, r3.Header().Get(HeaderReplay), r3.Body.String())
	}

	// 3) 同 msg_id 换 method → 不得回放（键含 method）
	hit = 0
	r4 := do(http.MethodPatch, "/v1/x", "same-id")
	if hit != 1 || r4.Header().Get(HeaderReplay) == "1" {
		t.Fatalf("跨 method 同 msg_id 不应串缓存：hit=%d replay=%q", hit, r4.Header().Get(HeaderReplay))
	}

	// 4) GET 直通：同 path 同 msg_id 两次都执行、无 replay 头
	hit = 0
	g1 := do(http.MethodGet, "/v1/x", "get-id")
	g2 := do(http.MethodGet, "/v1/x", "get-id")
	if hit != 2 {
		t.Fatalf("GET 应直通（每次都执行业务），实际执行 %d 次", hit)
	}
	if g1.Header().Get(HeaderReplay) != "" || g2.Header().Get(HeaderReplay) != "" {
		t.Fatal("GET 不应打 X-Idempotent-Replay（读接口不走写缓存）")
	}
}
