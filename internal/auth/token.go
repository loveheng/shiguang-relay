package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// 双 Token 口径（设计稿 §1.4）：access 短效（默认 2h，只存内存）、refresh 长效（默认 30d，存 secure_storage）。
// 网关无状态校验 access；refresh 仅用于换新，不用于访问业务接口。
var (
	ErrTokenInvalid = errors.New("token 无效或已过期")
	ErrTokenWrongType = errors.New("token 类型不符")
)

type TokenPair struct {
	AccessToken   string `json:"access_token"`
	RefreshToken  string `json:"refresh_token"`
	AccessExpires int64  `json:"access_expires_at"`
}

type Issuer struct {
	secret     []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewIssuer(secret []byte, accessTTL, refreshTTL time.Duration) *Issuer {
	return &Issuer{secret: secret, accessTTL: accessTTL, refreshTTL: refreshTTL}
}

func (i *Issuer) Issue(userID string) (TokenPair, error) {
	now := time.Now()
	access, err := i.sign(userID, "access", now, i.accessTTL)
	if err != nil {
		return TokenPair{}, err
	}
	refresh, err := i.sign(userID, "refresh", now, i.refreshTTL)
	if err != nil {
		return TokenPair{}, err
	}
	return TokenPair{
		AccessToken:   access,
		RefreshToken:  refresh,
		AccessExpires: now.Add(i.accessTTL).Unix(),
	}, nil
}

func (i *Issuer) sign(userID, typ string, now time.Time, ttl time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"typ": typ,
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

// Verify：校验签名与有效期并断言 typ（access 不能当 refresh 用，反之亦然）。
func (i *Issuer) Verify(tokenString, wantType string) (string, error) {
	claims := jwt.MapClaims{}
	// 显式白名单算法：杜绝 alg=none / 算法混淆类攻击
	parsed, err := jwt.ParseWithClaims(tokenString, claims, func(*jwt.Token) (any, error) {
		return i.secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !parsed.Valid {
		return "", ErrTokenInvalid
	}
	if typ, _ := claims["typ"].(string); typ != wantType {
		return "", ErrTokenWrongType
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", ErrTokenInvalid
	}
	return sub, nil
}
