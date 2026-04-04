package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/getpong/pong-backend-go/internal/model"
	"github.com/getpong/pong-backend-go/internal/store"
)

// HeartbeatHandler handles the public heartbeat ping endpoint.
type HeartbeatHandler struct {
	store *store.Store
}

// NewHeartbeatHandler returns a new HeartbeatHandler.
func NewHeartbeatHandler(s *store.Store) *HeartbeatHandler {
	return &HeartbeatHandler{store: s}
}

// Ping handles POST /api/v1/heartbeat/{token}.
// This is a PUBLIC endpoint (no auth required).
// It updates the heartbeat_last_ping timestamp for the monitor with the given token.
func (h *HeartbeatHandler) Ping(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if token == "" {
		respondError(w, http.StatusBadRequest, "missing heartbeat token")
		return
	}

	// Look up the monitor to check for a secret.
	monitor, err := h.store.GetMonitorByHeartbeatToken(r.Context(), token)
	if err != nil {
		respondError(w, http.StatusNotFound, "invalid heartbeat token")
		return
	}

	// If a secret is configured, validate the X-Secret header.
	if monitor.HeartbeatSecret != "" {
		if r.Header.Get("X-Secret") != monitor.HeartbeatSecret {
			respondError(w, http.StatusUnauthorized, "invalid or missing X-Secret header")
			return
		}
	}

	monitorID, err := h.store.UpdateHeartbeatPing(r.Context(), token)
	if err != nil {
		respondError(w, http.StatusNotFound, "invalid heartbeat token")
		return
	}

	// A ping IS the health signal — mark the monitor as up and record the check.
	now := time.Now()
	if err := h.store.UpdateMonitorStatus(r.Context(), monitorID, "up", now); err != nil {
		slog.Error("failed to update heartbeat monitor status", "monitor_id", monitorID, "error", err)
	}
	if err := h.store.ResetConsecutiveFails(r.Context(), monitorID); err != nil {
		slog.Error("failed to reset consecutive fails", "monitor_id", monitorID, "error", err)
	}
	if err := h.store.InsertCheckResult(r.Context(), &model.CheckResult{
		MonitorID: monitorID,
		Status:    "up",
		Message:   "Heartbeat ping received",
		CheckedAt: now,
	}); err != nil {
		slog.Error("failed to insert heartbeat check result", "monitor_id", monitorID, "error", err)
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"monitor_id": monitorID,
	})
}

// PingGet handles GET /api/v1/heartbeat/{token} — same behaviour as Ping
// but accepts GET requests for cron jobs and simple HTTP clients that only
// support GET.
func (h *HeartbeatHandler) PingGet(w http.ResponseWriter, r *http.Request) {
	h.Ping(w, r)
}
