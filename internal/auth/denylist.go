package auth

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// DenyList：jti 黑名单（撤销机制的两条腿之一，另一条是 EpochStore 全量踢）。
//
// 用途：
//   - refresh rotation：换新后旧 refresh jti 拉黑至原到期时刻 → 重用即拒（盗号止损）；
//   - 登出：access + refresh 双 jti 拉黑至各自到期。
//
// 粒度是单枚 token 实例（jti），与 EpochStore 的用户级全量撤销互补：
// 单点撤销走这里（O(1)、不影响该用户其他设备），改密全杀走纪元。
type DenyList struct {
	rdb *redis.Client
}

func NewDenyList(rdb *redis.Client) *DenyList {
	return &DenyList{rdb: rdb}
}

func denyKey(jti string) string { return "dl:" + jti }

// Add：拉黑 jti 至 ttl 期满（与 token 剩余寿命对齐，过期自动出池）。
// 空 jti（旧版本签发的 token）为 no-op——无实例号无法精确定位，只能等其自然到期。
func (d *DenyList) Add(ctx context.Context, jti string, ttl time.Duration) error {
	if jti == "" || ttl <= 0 {
		return nil
	}
	return d.rdb.Set(ctx, denyKey(jti), "1", ttl).Err()
}

// Has：jti 是否已被拉黑。Redis 故障返回 false（fail-open，与全库口径一致）。
func (d *DenyList) Has(ctx context.Context, jti string) bool {
	if jti == "" {
		return false
	}
	n, err := d.rdb.Exists(ctx, denyKey(jti)).Result()
	return err == nil && n > 0
}
