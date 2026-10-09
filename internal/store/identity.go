package store

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PGIdentity：auth.IdentityResolver 的生产实现（读 users.identity_key_pub）。
type PGIdentity struct{ Pool *pgxpool.Pool }

func (p PGIdentity) IdentityKey(ctx context.Context, userID string) ([]byte, error) {
	return IdentityKey(ctx, p.Pool, userID)
}
