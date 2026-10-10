package auth

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// EpochStore：用户令牌纪元（改密踢会话的机制核心）。
//
// 原理：改密时 Bump（ue:{userID} 自增）；token 签发时内嵌当时纪元 ver；
// 中间件/refresh 比对 ver < 当前纪元 → 一律拒绝。无状态 JWT 无法枚举某用户全部 token，
// 纪元是 O(1) 撤销「该用户所有既有会话」的最低成本方案。
//
// TTL 取 refresh TTL（与其保护对象同寿）：纪元键自然过期时，携带旧纪元的 token 也已全部到期，
// 不存在「纪元过期复活旧 token」的窗口。
//
// fail-open：Redis 故障时 Current 报错 → CheckEpoch 视为有效（与全库限流口径一致，
// 限流/撤销不是最后一道防线；最坏情形 = 改密后旧 token 存活至 access TTL 自然过期）。
type EpochStore struct {
	rdb *redis.Client
	ttl time.Duration
}

func NewEpochStore(rdb *redis.Client, ttl time.Duration) *EpochStore {
	return &EpochStore{rdb: rdb, ttl: ttl}
}

func epochKey(userID string) string { return "ue:" + userID }

// Current：当前纪元（键缺失 → 0，即从未改密）。
func (e *EpochStore) Current(ctx context.Context, userID string) (int64, error) {
	v, err := e.rdb.Get(ctx, epochKey(userID)).Result()
	if err != nil {
		if err == redis.Nil {
			return 0, nil
		}
		return 0, fmt.Errorf("读取令牌纪元失败: %w", err)
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("令牌纪元值损坏: %w", err)
	}
	return n, nil
}

// Bump：纪元 +1（改密/管理员踢会话时调用）；每次重设 TTL 窗口。
func (e *EpochStore) Bump(ctx context.Context, userID string) error {
	key := epochKey(userID)
	if err := e.rdb.Incr(ctx, key).Err(); err != nil {
		return fmt.Errorf("推进令牌纪元失败: %w", err)
	}
	_ = e.rdb.Expire(ctx, key, e.ttl).Err()
	return nil
}
