// Command relayd：拾光盲中继服务端。
// Phase 1.1：鉴权闭环（Challenge-Response + 双 Token + client_msg_id 幂等）。
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"shiguang-relay/internal/auth"
	"shiguang-relay/internal/config"
	"shiguang-relay/internal/httpapi"
	"shiguang-relay/internal/store"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		logger.Error("配置加载失败", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := store.NewPG(ctx, cfg.PGDSN)
	if err != nil {
		logger.Error("PostgreSQL 连接失败", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	rdb, err := store.NewRedis(ctx, cfg.RedisAddr)
	if err != nil {
		logger.Error("Redis 连接失败", "err", err)
		os.Exit(1)
	}
	defer rdb.Close()

	deps := httpapi.Deps{
		Issuer:      auth.NewIssuer(cfg.JWTSecret, cfg.AccessTTL, cfg.RefreshTTL),
		Challenges:  auth.NewChallengeStore(rdb, cfg.ChallengeTTL, cfg.PoWDifficulty),
		Idem:        auth.NewIdempotency(rdb, cfg.IdempotentTTL, cfg.IdempotentTTL),
		Identities:  store.PGIdentity{Pool: pool},
		PoWRequired: cfg.PoWRequired,

		Users:               store.UserStore{Pool: pool},
		Limiter:             auth.NewRateLimiter(rdb, cfg.RegisterLimitPerMin, time.Minute),
		RegisterLimitPerMin: cfg.RegisterLimitPerMin,
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           httpapi.NewRouter(deps),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		logger.Info("relayd 启动", "addr", cfg.Listen)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP 服务异常退出", "err", err)
			stop()
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("优雅退出超时", "err", err)
	}
	logger.Info("relayd 已停止")
}
