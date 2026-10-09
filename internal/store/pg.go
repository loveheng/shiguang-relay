package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPG：建立 PostgreSQL 连接池并探活。schema 见仓库 schema.sql（DDL 唯一出处）。
func NewPG(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("解析 PG DSN 失败: %w", err)
	}
	cfg.MaxConns = 8
	cfg.MinConns = 1
	cfg.MaxConnLifetime = 30 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("创建 PG 连接池失败: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("PG 探活失败: %w", err)
	}
	return pool, nil
}

// IdentityKey：取用户登记的 Ed25519 身份公钥（users.identity_key_pub）。
// 未登记返回 nil, nil —— 由调用方决定是 401 还是引导注册，不在数据层替业务做判断。
func IdentityKey(ctx context.Context, pool *pgxpool.Pool, userID string) ([]byte, error) {
	var pub []byte
	err := pool.QueryRow(ctx,
		`SELECT identity_key_pub FROM users WHERE user_id = $1`, userID).Scan(&pub)
	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("查询身份公钥失败: %w", err)
	}
	return pub, nil
}
