package checker

import (
	"context"
	"log/slog"
	"time"

	"github.com/getpong/pong-backend-go/internal/store"
)

// Pruner periodically deletes old check results and alert logs.
type Pruner struct {
	store         *store.Store
	retentionDays int
	interval      time.Duration
	done          chan struct{}
}

// NewPruner creates a pruner that runs every interval and deletes data older than retentionDays.
func NewPruner(s *store.Store, retentionDays int, interval time.Duration) *Pruner {
	return &Pruner{
		store:         s,
		retentionDays: retentionDays,
		interval:      interval,
		done:          make(chan struct{}),
	}
}

// Start runs the pruning loop. It blocks until ctx is cancelled.
func (p *Pruner) Start(ctx context.Context) {
	slog.Info("pruner started", "retention_days", p.retentionDays, "interval", p.interval)
	defer close(p.done)

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	// Run once at startup.
	p.prune(ctx)

	for {
		select {
		case <-ctx.Done():
			slog.Info("pruner stopping")
			return
		case <-ticker.C:
			p.prune(ctx)
		}
	}
}

// Done returns a channel that closes when the pruner has stopped.
func (p *Pruner) Done() <-chan struct{} {
	return p.done
}

func (p *Pruner) prune(ctx context.Context) {
	results, err := p.store.PruneCheckResults(ctx, p.retentionDays)
	if err != nil {
		slog.Error("failed to prune check results", "error", err)
	} else if results > 0 {
		slog.Info("pruned check results", "deleted", results)
	}

	logs, err := p.store.PruneAlertLogs(ctx, p.retentionDays)
	if err != nil {
		slog.Error("failed to prune alert logs", "error", err)
	} else if logs > 0 {
		slog.Info("pruned alert logs", "deleted", logs)
	}
}
