package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/getpong/pong-backend-go/internal/alerter"
	"github.com/getpong/pong-backend-go/internal/api"
	"github.com/getpong/pong-backend-go/internal/checker"
	"github.com/getpong/pong-backend-go/internal/config"
	"github.com/getpong/pong-backend-go/internal/model"
	"github.com/getpong/pong-backend-go/internal/store"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	db, err := store.NewSQLite(cfg.DatabasePath, cfg.EncryptionKey)
	if err != nil {
		slog.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	migrationsDir := "migrations"
	if _, err := os.Stat("/app/migrations"); err == nil {
		migrationsDir = "/app/migrations"
	}
	if v := os.Getenv("MIGRATIONS_DIR"); v != "" {
		migrationsDir = v
	}

	if err := db.Migrate(migrationsDir); err != nil {
		slog.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}

	// Bootstrap admin API key if configured (API-key-only mode).
	if cfg.AdminAPIKey != "" {
		if err := db.BootstrapAdminKey(context.Background(), cfg.AdminAPIKey); err != nil {
			slog.Error("failed to bootstrap admin key", "error", err)
			os.Exit(1)
		}
		if !cfg.Auth0Enabled() {
			slog.Info("running in API-key-only mode (no Auth0)")
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	alertCh := make(chan model.StateChangeEvent, 100)

	httpChecker := checker.NewHTTPChecker(db.DecryptMonitorAuth)
	sched := checker.NewScheduler(db, httpChecker, alertCh, cfg.WorkerCount, cfg.CheckTickSeconds)
	go sched.Start(ctx)

	alt := alerter.NewAlerter(db, alertCh, cfg)
	go alt.Start(ctx)

	pruner := checker.NewPruner(db, cfg.RetentionDays, 24*time.Hour)
	go pruner.Start(ctx)

	router := api.NewRouter(db, cfg)
	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: router,
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		slog.Info("server starting", "port", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	sig := <-sigCh
	slog.Info("shutdown signal received", "signal", sig)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown error", "error", err)
	}

	cancel()
	<-sched.Done()
	<-alt.Done()
	<-pruner.Done()

	slog.Info("shutdown complete")
}
