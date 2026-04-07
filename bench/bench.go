// Package bench provides a CLI tool to benchmark the health monitor backend.
// It creates N monitors pointing to a local echo server, runs the scheduler,
// and measures checks/second and DB writes/second.
//
// Usage: go run ./bench -monitors=1000 -workers=20 -duration=30s
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/getpong/pong-backend-go/internal/checker"
	"github.com/getpong/pong-backend-go/internal/model"
	"github.com/getpong/pong-backend-go/internal/store"
)

func main() {
	monitors := flag.Int("monitors", 500, "number of monitors to create")
	workers := flag.Int("workers", 20, "number of worker goroutines")
	duration := flag.Duration("duration", 30*time.Second, "benchmark duration")
	flag.Parse()

	slog.Info("benchmark config",
		"monitors", *monitors,
		"workers", *workers,
		"duration", *duration,
	)

	// Create temp database.
	dbPath := fmt.Sprintf("/tmp/ghm-bench-%d.db", time.Now().UnixNano())
	defer os.Remove(dbPath)

	db, err := store.New(dbPath, "")
	if err != nil {
		slog.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// Run migrations.
	if err := db.Migrate("migrations"); err != nil {
		slog.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}

	// Create a test user.
	userID, err := db.EnsureUser(context.Background(), "bench|user", "bench@test.com")
	if err != nil {
		slog.Error("failed to create user", "error", err)
		os.Exit(1)
	}

	// Start a local echo server that responds instantly.
	echoServer := &http.Server{Addr: ":19876"}
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"ok"}`))
	})
	go echoServer.ListenAndServe()
	defer echoServer.Close()
	time.Sleep(100 * time.Millisecond)

	// Create monitors pointing to the echo server.
	slog.Info("creating monitors...")
	for i := range *monitors {
		_, err := db.CreateMonitor(context.Background(), &model.Monitor{
			UserID:            userID,
			Name:              fmt.Sprintf("bench-%d", i),
			Type:              "http",
			Target:            "http://localhost:19876/health",
			IntervalSecs:      1, // 1 second so they're always due
			TimeoutSecs:       5,
			ExpectedStatus:    200,
			ConfirmationCount: 1,
			Enabled:           true,
			Status:            "unknown",
		})
		if err != nil {
			slog.Error("failed to create monitor", "error", err)
			os.Exit(1)
		}
	}
	slog.Info("monitors created", "count", *monitors)

	// Track checks.
	var totalChecks atomic.Int64
	alertCh := make(chan model.StateChangeEvent, 1000)

	// Drain alert channel.
	go func() {
		for range alertCh {
		}
	}()

	// Start scheduler.
	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()

	httpChecker := checker.NewHTTPChecker(nil)
	sched := checker.NewScheduler(db, httpChecker, alertCh, *workers, 1)

	// Count check results by polling DB.
	startCount := countResults(db)
	startTime := time.Now()

	go sched.Start(ctx)

	// Progress ticker.
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	go func() {
		for {
			select {
			case <-ticker.C:
				current := countResults(db) - startCount
				elapsed := time.Since(startTime).Seconds()
				slog.Info("progress",
					"checks", current,
					"checks_per_sec", fmt.Sprintf("%.1f", float64(current)/elapsed),
					"elapsed", fmt.Sprintf("%.0fs", elapsed),
				)
			case <-ctx.Done():
				return
			}
		}
	}()

	<-ctx.Done()
	<-sched.Done()

	// Final stats.
	endCount := countResults(db) - startCount
	elapsed := time.Since(startTime).Seconds()
	checksPerSec := float64(endCount) / elapsed
	_ = totalChecks.Load()

	fmt.Println()
	fmt.Println("=== Benchmark Results ===")
	fmt.Printf("Monitors:        %d\n", *monitors)
	fmt.Printf("Workers:         %d\n", *workers)
	fmt.Printf("Duration:        %s\n", *duration)
	fmt.Printf("Total checks:    %d\n", endCount)
	fmt.Printf("Checks/sec:      %.1f\n", checksPerSec)
	fmt.Printf("DB writes/sec:   %.1f (3x checks: result + status + fails)\n", checksPerSec*3)
	fmt.Println()
	fmt.Println("=== Capacity Estimates ===")
	fmt.Printf("At 1min interval:  %d monitors\n", int(checksPerSec*60))
	fmt.Printf("At 5min interval:  %d monitors\n", int(checksPerSec*300))
	fmt.Printf("At 30s interval:   %d monitors\n", int(checksPerSec*30))
}

func countResults(db *store.Store) int64 {
	var count int64
	db.DB().QueryRow("SELECT COUNT(*) FROM check_results").Scan(&count)
	return count
}
