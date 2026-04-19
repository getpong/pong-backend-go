package checker

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/getpong/pong-backend-go/internal/model"
	"github.com/getpong/pong-backend-go/internal/store"
)

// Scheduler periodically fetches due monitors and dispatches health checks
// across a pool of worker goroutines.
type Scheduler struct {
	store            store.CheckerStore
	httpChecker      Checker
	sslChecker       Checker
	heartbeatChecker Checker
	portChecker      Checker
	dnsChecker       Checker
	alertCh          chan model.StateChangeEvent
	workerCount      int
	tickInterval     time.Duration
	done             chan struct{}
}

// NewScheduler creates a new Scheduler. It accepts an HTTP checker (used for
// "http" and "keyword" monitor types) and creates SSL and heartbeat checkers
// internally. For backwards compatibility, if only an HTTP checker is needed
// callers may pass it as the checker argument.
func NewScheduler(s store.CheckerStore, checker Checker, alertCh chan model.StateChangeEvent, workerCount int, tickSeconds int) *Scheduler {
	return &Scheduler{
		store:            s,
		httpChecker:      checker,
		sslChecker:       &SSLChecker{},
		heartbeatChecker: &HeartbeatChecker{},
		portChecker:      &PortChecker{},
		dnsChecker:       &DNSChecker{},
		alertCh:          alertCh,
		workerCount:      workerCount,
		tickInterval:     time.Duration(tickSeconds) * time.Second,
		done:             make(chan struct{}),
	}
}

// Start begins the tick loop and worker pool. It blocks until ctx is cancelled.
func (s *Scheduler) Start(ctx context.Context) {
	jobs := make(chan model.Monitor, s.workerCount*2)

	var wg sync.WaitGroup

	// Start worker pool.
	for i := range s.workerCount {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			s.worker(ctx, id, jobs)
		}(i)
	}

	slog.Info("scheduler started", "workers", s.workerCount, "tick_interval", s.tickInterval)

	ticker := time.NewTicker(s.tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("scheduler stopping: context cancelled")
			close(jobs)
			wg.Wait()
			close(s.done)
			return
		case <-ticker.C:
			s.tick(ctx, jobs)
		}
	}
}

// Done returns a channel that is closed when the scheduler has fully stopped.
func (s *Scheduler) Done() <-chan struct{} {
	return s.done
}

func (s *Scheduler) tick(ctx context.Context, jobs chan<- model.Monitor) {
	monitors, err := s.store.GetDueMonitors(ctx)
	if err != nil {
		slog.Error("failed to get due monitors", "error", err)
		return
	}

	if len(monitors) > 0 {
		slog.Debug("dispatching monitors", "count", len(monitors))
	}

	for _, m := range monitors {
		// Mark as checked immediately to prevent re-queuing on the next tick
		// while the check is still in progress.
		s.store.UpdateMonitorStatus(ctx, m.ID, m.Status, time.Now())

		select {
		case jobs <- m:
		case <-ctx.Done():
			return
		}
	}
}

// checkerFor returns the appropriate Checker for the given monitor type.
func (s *Scheduler) checkerFor(monitorType string) Checker {
	switch monitorType {
	case "ssl":
		return s.sslChecker
	case "heartbeat":
		return s.heartbeatChecker
	case "port":
		return s.portChecker
	case "dns":
		return s.dnsChecker
	default:
		// "http", "keyword" and any future types default to HTTP.
		return s.httpChecker
	}
}

func (s *Scheduler) worker(ctx context.Context, id int, jobs <-chan model.Monitor) {
	slog.Debug("worker started", "worker_id", id)

	for m := range jobs {
		checker := s.checkerFor(m.Type)
		result := checker.Check(ctx, m)

		// Skip DB writes if context is cancelled (graceful shutdown).
		if ctx.Err() != nil {
			continue
		}

		// For SSL monitors, extract and persist the certificate expiry date.
		if m.Type == "ssl" {
			if expiryAt, ok := parseSSLExpiry(result.Message); ok {
				if err := s.store.UpdateSSLExpiry(ctx, m.ID, expiryAt); err != nil {
					slog.Error("failed to update SSL expiry",
						"monitor_id", m.ID,
						"error", err,
					)
				}
			}
		}

		// Confirmation count logic: only transition to "down" after
		// consecutive_fails >= confirmation_count.
		confirmationCount := m.ConfirmationCount
		if confirmationCount < 1 {
			confirmationCount = 1
		}

		effectiveStatus := result.Status
		resetFails := true
		newFailCount := m.ConsecutiveFails + 1

		if result.Status == "down" {
			resetFails = false
			if newFailCount < confirmationCount {
				effectiveStatus = m.Status
				slog.Debug("failure not yet confirmed",
					"monitor_id", m.ID,
					"consecutive_fails", newFailCount,
					"confirmation_count", confirmationCount,
				)
			}
		}

		// Persist check result + monitor state update in a single transaction.
		if err := s.store.SaveCheckResult(ctx, m.ID, &result, effectiveStatus, resetFails, newFailCount); err != nil {
			slog.Error("failed to save check result",
				"monitor_id", m.ID,
				"error", err,
			)
		}

		// Detect state change. Only fire alerts on transitions between "up" and "down".
		// Skip the initial transition from "unknown" — it's not a real state change.
		if m.Status != effectiveStatus && m.Status != "" && m.Status != "unknown" {
			event := model.StateChangeEvent{
				Monitor:   m,
				OldStatus: m.Status,
				NewStatus: effectiveStatus,
				Result:    result,
			}
			slog.Info("monitor state changed",
				"monitor_id", m.ID,
				"name", m.Name,
				"old_status", m.Status,
				"new_status", effectiveStatus,
			)
			select {
			case s.alertCh <- event:
			default:
				slog.Warn("alert channel full, dropping state change event",
					"monitor_id", m.ID,
				)
			}
		}
	}

	slog.Debug("worker stopped", "worker_id", id)
}

// parseSSLExpiry extracts the certificate expiry time from an SSLChecker
// result message. The message format is "SSL_EXPIRY:<RFC3339> ...".
func parseSSLExpiry(msg string) (time.Time, bool) {
	const prefix = "SSL_EXPIRY:"
	if !strings.HasPrefix(msg, prefix) {
		return time.Time{}, false
	}
	rest := msg[len(prefix):]
	// The RFC3339 timestamp ends at the first space.
	if idx := strings.Index(rest, " "); idx != -1 {
		rest = rest[:idx]
	}
	t, err := time.Parse(time.RFC3339, rest)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
