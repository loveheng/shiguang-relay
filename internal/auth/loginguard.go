package auth

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// LoginGuard：登录失败锁定（账号维度，Plan A 防爆破第二桶）。
//
// 与 RateLimiter（IP 维度、计数所有请求）互补：
//   - IP 桶挡分布式扫射（spray）；
//   - 账号桶挡定点爆破（针对单一 username 的字典攻击）。
//
// 语义：固定窗口失败计数——首个失败起算 window，窗口内失败 ≥ maxFails 即锁定；
// 登录成功立即清零（正主不受历史失败拖累）。
//
// 已知取舍：账号维度锁定可被恶意者用来短暂锁定受害者（login DoS）。
// 接受理由：IP 限流先行收窄攻击面（攻击者需大量 IP 才能长期锁定正主），
// 且宁可短暂误伤也不给爆破留窗口——与全库「限流不是最后一道防线」的可用性哲学一致。
type LoginGuard struct {
	rdb      *redis.Client
	maxFails int
	window   time.Duration
}

func NewLoginGuard(rdb *redis.Client, maxFails int, window time.Duration) *LoginGuard {
	return &LoginGuard{rdb: rdb, maxFails: maxFails, window: window}
}

func loginFailKey(ident string) string { return "lt:" + ident }

// Blocked：账号是否处于失败锁定窗口内。Redis 故障返回 false（放行，与全库限流口径一致）。
func (g *LoginGuard) Blocked(ctx context.Context, ident string) (bool, error) {
	n, err := g.rdb.Get(ctx, loginFailKey(ident)).Int()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return false, nil
		}
		return false, err
	}
	return n >= g.maxFails, nil
}

// RecordFail：记一次失败；首个失败起算 window（INCR + 仅首次 EXPIRE）。
func (g *LoginGuard) RecordFail(ctx context.Context, ident string) error {
	key := loginFailKey(ident)
	n, err := g.rdb.Incr(ctx, key).Result()
	if err != nil {
		return err
	}
	if n == 1 {
		_ = g.rdb.Expire(ctx, key, g.window).Err()
	}
	return nil
}

// Reset：登录成功清零（不计失败台账）。
func (g *LoginGuard) Reset(ctx context.Context, ident string) {
	_ = g.rdb.Del(ctx, loginFailKey(ident)).Err()
}
