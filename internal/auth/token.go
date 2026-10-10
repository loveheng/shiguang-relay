package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// 双 Token 口径（设计稿 §1.4）：access 短效（默认 2h，只存内存）、refresh 长效（默认 30d，存 secure_storage）。
// 网关无状态校验 access；refresh 仅用于换新，不用于访问业务接口。
//
// 撤销语义（v0.1.7 防爆破/止损补全）：
//   - 每枚 token 内嵌 jti（唯一实例号）——供 DenyList 按 jti 拉黑（refresh rotation 重用检测 / 登出）；
//   - 每枚 token 内嵌 ver（签发时的用户令牌纪元）——改密时 EpochStore.Bump 全量踢旧会话，
//     中间件比对 ver < 当前纪元即拒（access 与 refresh 双双失效）。
var (
	ErrTokenInvalid   = errors.New("token 无效或已过期")
	ErrTokenWrongType = errors.New("token 类型不符")
)

type TokenPair struct {
	AccessToken   string `json:"access_token"`
	RefreshToken  string `json:"refresh_token"`
	AccessExpires int64  `json:"access_expires_at"`
}

// Claims：业务侧所需的 token 载荷子集。
type Claims struct {
	UserID string
	Type   string // "access" | "refresh"
	JTI    string // 唯一实例号（旧版本签发的 token 无此字段 → 空串，拉黑类操作对空 jti 空转）
	Ver    int64  // 签发时用户令牌纪元（无字段视为 0）
	Expiry int64  // unix 秒
}

type Issuer struct {
	secret     []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
	epoch      *EpochStore // 可选；nil 时 ver 恒 0（无改密踢会话能力）
	deny       *DenyList   // 可选；nil 时不查 jti 黑名单（无登出/rotation 重用检测）
}

func NewIssuer(secret []byte, accessTTL, refreshTTL time.Duration) *Issuer {
	return &Issuer{secret: secret, accessTTL: accessTTL, refreshTTL: refreshTTL}
}

// SetEpoch：注入用户令牌纪元存储（改密踢会话）。须在服务启动装配期调用一次。
func (i *Issuer) SetEpoch(e *EpochStore) { i.epoch = e }

// SetDeny：注入 jti 黑名单（登出 / refresh rotation 重用检测）。须在服务启动装配期调用一次。
func (i *Issuer) SetDeny(d *DenyList) { i.deny = d }

// Revoked：jti 是否已被拉黑（黑名单缺失/故障 fail-open）。
func (i *Issuer) Revoked(ctx context.Context, jti string) bool {
	return i.deny != nil && i.deny.Has(ctx, jti)
}

// Issue：签发双 Token（内嵌 jti + 当前纪元 ver）。
func (i *Issuer) Issue(ctx context.Context, userID string) (TokenPair, error) {
	now := time.Now()
	ver := int64(0)
	if i.epoch != nil {
		if v, err := i.epoch.Current(ctx, userID); err == nil {
			ver = v
		}
		// 纪元读取失败按 ver=0 签发（fail-open）：下一轮改密 Bump 到 ≥1 时自然补杀
	}
	access, err := i.sign(userID, "access", now, i.accessTTL, ver)
	if err != nil {
		return TokenPair{}, err
	}
	refresh, err := i.sign(userID, "refresh", now, i.refreshTTL, ver)
	if err != nil {
		return TokenPair{}, err
	}
	return TokenPair{
		AccessToken:   access,
		RefreshToken:  refresh,
		AccessExpires: now.Add(i.accessTTL).Unix(),
	}, nil
}

func randJTI() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (i *Issuer) sign(userID, typ string, now time.Time, ttl time.Duration, ver int64) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"typ": typ,
		"jti": randJTI(),
		"ver": ver,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(i.secret)
	if err != nil {
		return "", fmt.Errorf("签发 %s token 失败: %w", typ, err)
	}
	return signed, nil
}

// VerifyClaims：校验签名与有效期并断言 typ，返回完整业务载荷。
// 显式白名单算法：杜绝 alg=none / 算法混淆类攻击。
func (i *Issuer) VerifyClaims(tokenString, wantType string) (Claims, error) {
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(tokenString, claims, func(*jwt.Token) (any, error) {
		return i.secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !parsed.Valid {
		return Claims{}, ErrTokenInvalid
	}
	typ, _ := claims["typ"].(string)
	if typ != wantType {
		return Claims{}, ErrTokenWrongType
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return Claims{}, ErrTokenInvalid
	}
	num := func(k string) int64 {
		f, _ := claims[k].(float64)
		return int64(f)
	}
	jti, _ := claims["jti"].(string)
	return Claims{
		UserID: sub,
		Type:   typ,
		JTI:    jti,
		Ver:    num("ver"),
		Expiry: num("exp"),
	}, nil
}

// CheckEpoch：token 纪元是否仍有效（ver >= 当前纪元；纪元存储缺失/故障 fail-open）。
func (i *Issuer) CheckEpoch(ctx context.Context, userID string, ver int64) bool {
	if i.epoch == nil {
		return true
	}
	cur, err := i.epoch.Current(ctx, userID)
	if err != nil {
		return true
	}
	return ver >= cur
}

// Verify：兼容旧口径（只取 user_id）——WSS Hub 与存量调用方使用。
func (i *Issuer) Verify(tokenString, wantType string) (string, error) {
	c, err := i.VerifyClaims(tokenString, wantType)
	if err != nil {
		return "", err
	}
	return c.UserID, nil
}
