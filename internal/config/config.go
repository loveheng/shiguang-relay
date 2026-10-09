package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config：服务端运行参数，全部来自环境变量（docker-compose.yml 已给出本地默认值）。
type Config struct {
	Listen        string        // HTTP/WSS 监听地址
	PGDSN         string        // PostgreSQL DSN
	RedisAddr     string        // Redis 地址
	JWTSecret     []byte        // 双 Token 签名密钥（HMAC-SHA256）
	AccessTTL     time.Duration // access_token 有效期（设计稿 §1.4 定 2h）
	RefreshTTL    time.Duration // refresh_token 有效期
	ChallengeTTL  time.Duration // nonce 有效期（§1.4 定 60s）
	IdempotentTTL time.Duration // client_msg_id 去重窗口（§1.4 定 300s）
	PoWDifficulty int           // Hashcash 前导 0 位数（仅挡最低级扫描器）
	PoWRequired   bool          // 是否强制校验 PoW（本地联调可关，公网部署必须开）

	RegisterLimitPerMin int // 单 IP 每分钟注册上限（fact §7.1-2：≤3~5）

	FriendInviteLimitPerMin int // 单用户每分钟好友邀请上限（防撞库骚扰）
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def, lo, hi int) int {
	raw := os.Getenv(k)
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < lo || v > hi {
		return def
	}
	return v
}

func envDur(k string, def time.Duration) (time.Duration, error) {
	raw := os.Getenv(k)
	if raw == "" {
		return def, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("env %s 需为正整数秒，实际 %q", k, raw)
	}
	return time.Duration(v) * time.Second, nil
}

// Load：读取并校验配置。缺 JWTSecret 直接失败——弱密钥会让无状态网关形同虚设。
func Load() (Config, error) {
	accessTTL, err := envDur("RELAY_ACCESS_TTL_SEC", 2*time.Hour)
	if err != nil {
		return Config{}, err
	}
	refreshTTL, err := envDur("RELAY_REFRESH_TTL_SEC", 30*24*time.Hour)
	if err != nil {
		return Config{}, err
	}
	challengeTTL, err := envDur("RELAY_CHALLENGE_TTL_SEC", 60*time.Second)
	if err != nil {
		return Config{}, err
	}
	idemTTL, err := envDur("RELAY_IDEMPOTENT_TTL_SEC", 300*time.Second)
	if err != nil {
		return Config{}, err
	}

	secret := os.Getenv("RELAY_JWT_SECRET")
	if len(secret) < 32 {
		return Config{}, fmt.Errorf("RELAY_JWT_SECRET 缺失或短于 32 字节（当前 %d），拒绝启动", len(secret))
	}

	diff := 4
	if raw := os.Getenv("RELAY_POW_DIFFICULTY"); raw != "" {
		d, err := strconv.Atoi(raw)
		if err != nil || d < 0 || d > 8 {
			return Config{}, fmt.Errorf("env RELAY_POW_DIFFICULTY 需在 0..8，实际 %q", raw)
		}
		diff = d
	}

	return Config{
		Listen:        env("RELAY_LISTEN", ":8080"),
		PGDSN:         env("RELAY_PG_DSN", "postgres://relay:relay@localhost:5432/relay?sslmode=disable"),
		RedisAddr:     env("RELAY_REDIS_ADDR", "localhost:6379"),
		JWTSecret:     []byte(secret),
		AccessTTL:     accessTTL,
		RefreshTTL:    refreshTTL,
		ChallengeTTL:  challengeTTL,
		IdempotentTTL: idemTTL,
		PoWDifficulty: diff,
		// 关闭开关仅用于本地联调（RELAY_POW_OFF=1）；生产默认开启。
		PoWRequired: os.Getenv("RELAY_POW_OFF") != "1",

		// 单 IP 注册限流：默认 3/min（Sybil 三防线之一）
		RegisterLimitPerMin: envInt("RELAY_REGISTER_LIMIT_PER_MIN", 3, 1, 20),

		// 好友邀请限流：默认 10/min（Ticket 制已防撞库，此为第二层）
		FriendInviteLimitPerMin: envInt("RELAY_FRIEND_INVITE_LIMIT_PER_MIN", 10, 1, 60),
	}, nil
}
