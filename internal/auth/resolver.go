package auth

import "context"

// IdentityResolver：取用户登记的 Ed25519 身份公钥。
// 生产实现走 users.identity_key_pub（store.PGIdentity）；测试可注入假实现，无需真 PG。
type IdentityResolver interface {
	IdentityKey(ctx context.Context, userID string) ([]byte, error)
}
