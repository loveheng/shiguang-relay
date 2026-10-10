package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"shiguang-relay/internal/apierr"
	"shiguang-relay/internal/auth"
	"shiguang-relay/internal/httpapi"
)

// newLoginDeps：在基础 Deps 上挂登录防爆破双桶（miniredis 共享 rdb）。
// ipLimit=每分钟 IP 桶上限；maxFails/window=账号桶失败阈值与锁定窗口。
func newLoginDeps(t *testing.T, mr *miniredis.Miniredis, ipLimit, maxFails int, lockWindow time.Duration) httpapi.Deps {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	deps := newDeps(t)
	deps.LoginLimiter = auth.NewRateLimiter(rdb, ipLimit, time.Minute)
	deps.LoginGuard = auth.NewLoginGuard(rdb, maxFails, lockWindow)
	deps.LoginLockWindow = lockWindow
	return deps
}

// postLogin：发一次登录请求，返回原始响应（调用方自行断言与关闭）。
func postLogin(t *testing.T, srv *httptest.Server, username, password string) *http.Response {
	t.Helper()
	return doJSON(t, srv, http.MethodPost, "/v1/auth/login",
		fmt.Sprintf(`{"username":%q,"password":%q}`, username, password), randomID("lt"), "")
}

// errorCode：读响应体 error_code。
func errorCode(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	var body apierr.Body
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("解析错误响应体失败: %v", err)
	}
	return body.ErrorCode
}

// TestLoginIPRateLimited：IP 桶计数所有请求（含失败），超限 429 且错误码 LOGIN_THROTTLED。
func TestLoginIPRateLimited(t *testing.T) {
	mr := miniredis.RunT(t)
	srv := httptest.NewServer(httpapi.NewRouter(newLoginDeps(t, mr, 2, 5, time.Minute)))
	defer srv.Close()

	// 2 次失败登录耗尽 IP 桶
	for i := 0; i < 2; i++ {
		resp := postLogin(t, srv, "user-1", "wrong")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("第 %d 次失败登录期望 401，实际 %d", i+1, resp.StatusCode)
		}
		resp.Body.Close()
	}

	// 第 3 次（即便密码正确）→ 429
	resp := postLogin(t, srv, "user-1", "pass")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("超限登录期望 429，实际 %d", resp.StatusCode)
	}
	if code := errorCode(t, resp); code != apierr.LoginThrottled {
		t.Fatalf("错误码期望 LOGIN_THROTTLED，实际 %s", code)
	}
}

// TestLoginFailLockout：账号桶仅计失败，达阈值后正确密码也被锁；窗口过后恢复。
func TestLoginFailLockout(t *testing.T) {
	mr := miniredis.RunT(t)
	srv := httptest.NewServer(httpapi.NewRouter(newLoginDeps(t, mr, 1000, 2, time.Minute)))
	defer srv.Close()

	// 2 次错密码 → 触发锁定阈值
	for i := 0; i < 2; i++ {
		resp := postLogin(t, srv, "user-1", "wrong")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("失败登录期望 401，实际 %d", resp.StatusCode)
		}
		resp.Body.Close()
	}

	// 第 3 次即便密码正确也 429（锁定窗口内）
	resp := postLogin(t, srv, "user-1", "pass")
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("锁定期登录期望 429，实际 %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 锁定窗口过后恢复（正主可正常登录）
	mr.FastForward(2 * time.Minute)
	resp2 := postLogin(t, srv, "user-1", "pass")
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("锁定过期后期望 200，实际 %d", resp2.StatusCode)
	}
}

// TestLoginSuccessResetsFailCount：成功登录清零失败台账，正主不受历史失败拖累。
func TestLoginSuccessResetsFailCount(t *testing.T) {
	mr := miniredis.RunT(t)
	srv := httptest.NewServer(httpapi.NewRouter(newLoginDeps(t, mr, 1000, 2, time.Minute)))
	defer srv.Close()

	// 错 1 次 + 对 1 次（清零）→ 再错 1 次不应锁定（计数仅 1 < 2）
	postLogin(t, srv, "user-1", "wrong").Body.Close()
	respOK := postLogin(t, srv, "user-1", "pass")
	if respOK.StatusCode != http.StatusOK {
		t.Fatalf("正确登录期望 200，实际 %d", respOK.StatusCode)
	}
	respOK.Body.Close()

	resp := postLogin(t, srv, "user-1", "wrong")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("失败登录期望 401，实际 %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 计数 1/2：正确密码仍可登录
	resp2 := postLogin(t, srv, "user-1", "pass")
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("未达阈值时期望 200，实际 %d", resp2.StatusCode)
	}
	resp2.Body.Close()

	// 再错 2 次 → 达阈值 → 正确密码也 429
	for i := 0; i < 2; i++ {
		postLogin(t, srv, "user-1", "wrong").Body.Close()
	}
	resp3 := postLogin(t, srv, "user-1", "pass")
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("达阈值后期望 429，实际 %d", resp3.StatusCode)
	}
}
