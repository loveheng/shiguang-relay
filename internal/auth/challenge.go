package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Challenge：POST /v1/auth/challenge 的响应体（对应 relay_protocol.proto 的 AuthChallenge）。
type Challenge struct {
	Nonce         string `json:"nonce"`
	PowChallenge  string `json:"pow_challenge"`
	PowDifficulty int    `json:"pow_difficulty"`
	ExpiresAt     int64  `json:"expires_at"`
}

// challengePayload：nonce 在 Redis 内的绑定值（用户 + 该 nonce 对应的 PoW 题面）。
type challengePayload struct {
	UserID string `json:"user_id"`
	Pow    string `json:"pow"`
}

// ChallengeStore：nonce 的一次性签发与消费（Redis SETEX，用完即删）。
type ChallengeStore struct {
	rdb        *redis.Client
	ttl        time.Duration
	difficulty int
}

func NewChallengeStore(rdb *redis.Client, ttl time.Duration, difficulty int) *ChallengeStore {
	return &ChallengeStore{rdb: rdb, ttl: ttl, difficulty: difficulty}
}

// Difficulty：当前 PoW 难度（登录校验需与签发时一致）。
func (s *ChallengeStore) Difficulty() int { return s.difficulty }

func randHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// Issue：签发 nonce（32B 随机）+ PoW 题面（16B 随机），限时绑定 user_id。
// 未注册用户同样签发（避免 account 枚举侧信道）；验签阶段查不到公钥自然 401。
func (s *ChallengeStore) Issue(ctx context.Context, userID string) (Challenge, error) {
	nonce, err := randHex(32)
	if err != nil {
		return Challenge{}, fmt.Errorf("生成 nonce 失败: %w", err)
	}
	pow, err := randHex(16)
	if err != nil {
		return Challenge{}, fmt.Errorf("生成 PoW challenge 失败: %w", err)
	}
	val, err := json.Marshal(challengePayload{UserID: userID, Pow: pow})
	if err != nil {
		return Challenge{}, err
	}
	if err := s.rdb.Set(ctx, challengeKey(nonce), val, s.ttl).Err(); err != nil {
		return Challenge{}, fmt.Errorf("写入 nonce 失败: %w", err)
	}
	return Challenge{
		Nonce:         nonce,
		PowChallenge:  pow,
		PowDifficulty: s.difficulty,
		ExpiresAt:     time.Now().Add(s.ttl).Unix(),
	}, nil
}

// Consume：原子取出并删除 nonce（GETDEL）。
// 未命中（过期/已用过）返回 ok=false —— 调用方按 CHALLENGE_INVALID 401 处理。
func (s *ChallengeStore) Consume(ctx context.Context, nonce string) (userID, pow string, ok bool, err error) {
	raw, err := s.rdb.GetDel(ctx, challengeKey(nonce)).Result()
	if err == redis.Nil {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, fmt.Errorf("消费 nonce 失败: %w", err)
	}
	var p challengePayload
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return "", "", false, fmt.Errorf("nonce 绑定值损坏: %w", err)
	}
	return p.UserID, p.Pow, true, nil
}

// ClaimTicketNonce：好友 Ticket 的 nonce 一次性占位（SETNX + TTL）。
// 抢到 = 首次使用；抢不到 = 该 nonce 已用过（重放旧名片应被拒）。
// TTL 取「距过期时间」与 5 分钟取大者：过期票本身已拦，这里只防窗口内重放。
func (s *ChallengeStore) ClaimTicketNonce(ctx context.Context, issuer, nonce string, expiresAt int64) (bool, error) {
	ttl := time.Until(time.Unix(expiresAt, 0))
	if ttl < 5*time.Minute {
		ttl = 5 * time.Minute
	}
	ok, err := s.rdb.SetNX(ctx, ticketNonceKey(issuer, nonce), "1", ttl).Result()
	if err != nil {
		return false, fmt.Errorf("占位 ticket nonce 失败: %w", err)
	}
	return ok, nil
}

func challengeKey(nonce string) string { return "chal:" + nonce }

func ticketNonceKey(issuer, nonce string) string { return "ft:" + issuer + ":" + nonce }

func idempotencyKey(msgID string) string { return "idem:" + msgID }
