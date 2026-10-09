package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RateLimiter：固定窗口限流（Redis INCR + EXPIRE）。
//
// 定位（fact §7.1-2）：单 IP 注册限流是 Sybil 防线的三根支柱之一
// （另两根=注册孤岛无害化 + OPK 注册瘦身），不是可选项。
type RateLimiter struct {
	rdb    *redis.Client
	limit  int
	window time.Duration
}

func NewRateLimiter(rdb *redis.Client, limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{rdb: rdb, limit: limit, window: window}
}

// Allow：窗口内第 n 次请求，n <= limit 放行；返回剩余配额。
// Redis 故障时「放行」（可用性优先）——限流不是安全边界的最后一道，宁可少拦不阻断注册。
func (l *RateLimiter) Allow(ctx context.Context, bucket, ident string) (bool, int, error) {
	key := fmt.Sprintf("rl:%s:%s:%d", bucket, ident, time.Now().Unix()/int64(l.window.Seconds()))
	n, err := l.rdb.Incr(ctx, key).Result()
	if err != nil {
		return true, l.limit, err
	}
	if n == 1 {
		_ = l.rdb.Expire(ctx, key, l.window).Err()
	}
	remaining := l.limit - int(n)
	if remaining < 0 {
		remaining = 0
	}
	return int(n) <= l.limit, remaining, nil
}
