package api

import (
	"net/http"

	"github.com/getpong/pong-backend-go/internal/config"
	"github.com/getpong/pong-backend-go/internal/store"
)

// NewRouter sets up all HTTP routes and returns the top-level handler.
func NewRouter(s store.APIStore, cfg *config.Config) http.Handler {
	mux := http.NewServeMux()

	monitors := NewMonitorHandler(s, cfg)
	alerts := NewAlertHandler(s, cfg)
	heartbeat := NewHeartbeatHandler(s)
	statusPages := NewStatusPageHandler(s)
	apiKeys := NewAPIKeyHandler(s)
	admin := NewAdminHandler(s)

	var authMW func(http.Handler) http.Handler
	if cfg.Auth0Enabled() {
		authMW = Auth0Middleware(cfg.Auth0Domain, cfg.Auth0Audience, s, s)
	} else {
		authMW = APIKeyOnlyMiddleware(s)
	}
	adminMW := AdminMiddleware(s)

	// Health check
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Current user (protected)
	mux.Handle("GET /api/v1/me", authMW(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := UserIDFromContext(r.Context())
		user, err := s.GetUserByID(r.Context(), userID)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to get user")
			return
		}
		respondJSON(w, http.StatusOK, user)
	})))

	// Monitor routes (protected)
	mux.Handle("GET /api/v1/monitors", authMW(http.HandlerFunc(monitors.List)))
	mux.Handle("POST /api/v1/monitors", authMW(http.HandlerFunc(monitors.Create)))
	mux.Handle("GET /api/v1/monitors/{id}", authMW(http.HandlerFunc(monitors.Get)))
	mux.Handle("PUT /api/v1/monitors/{id}", authMW(http.HandlerFunc(monitors.Update)))
	mux.Handle("DELETE /api/v1/monitors/{id}", authMW(http.HandlerFunc(monitors.Delete)))
	mux.Handle("POST /api/v1/monitors/{id}/pause", authMW(http.HandlerFunc(monitors.Pause)))
	mux.Handle("POST /api/v1/monitors/{id}/resume", authMW(http.HandlerFunc(monitors.Resume)))
	mux.Handle("GET /api/v1/monitors/{id}/results", authMW(http.HandlerFunc(monitors.Results)))
	mux.Handle("GET /api/v1/monitors/{id}/uptime", authMW(http.HandlerFunc(monitors.Uptime)))
	mux.Handle("GET /api/v1/monitors/{id}/uptime/daily", authMW(http.HandlerFunc(monitors.DailyUptime)))
	mux.Handle("POST /api/v1/monitors/{id}/check", authMW(http.HandlerFunc(monitors.CheckNow)))
	mux.Handle("POST /api/v1/monitors/{id}/reset", authMW(http.HandlerFunc(monitors.ResetHistory)))

	// Alert contact routes (protected)
	mux.Handle("GET /api/v1/alert-contacts", authMW(http.HandlerFunc(alerts.ListContacts)))
	mux.Handle("POST /api/v1/alert-contacts", authMW(http.HandlerFunc(alerts.CreateContact)))
	mux.Handle("PUT /api/v1/alert-contacts/{id}", authMW(http.HandlerFunc(alerts.UpdateContact)))
	mux.Handle("DELETE /api/v1/alert-contacts/{id}", authMW(http.HandlerFunc(alerts.DeleteContact)))
	mux.Handle("POST /api/v1/alert-contacts/{id}/test", authMW(http.HandlerFunc(alerts.TestContact)))
	mux.Handle("POST /api/v1/alert-contacts/{id}/resend", authMW(http.HandlerFunc(alerts.ResendVerification)))
	mux.HandleFunc("GET /verify-email/{token}", alerts.VerifyContact)

	// Status page routes (protected)
	mux.Handle("GET /api/v1/status-pages", authMW(http.HandlerFunc(statusPages.List)))
	mux.Handle("POST /api/v1/status-pages", authMW(http.HandlerFunc(statusPages.Create)))
	mux.Handle("GET /api/v1/status-pages/{id}", authMW(http.HandlerFunc(statusPages.Get)))
	mux.Handle("PUT /api/v1/status-pages/{id}", authMW(http.HandlerFunc(statusPages.Update)))
	mux.Handle("DELETE /api/v1/status-pages/{id}", authMW(http.HandlerFunc(statusPages.Delete)))

	// API key routes (protected)
	mux.Handle("GET /api/v1/api-keys", authMW(http.HandlerFunc(apiKeys.List)))
	mux.Handle("POST /api/v1/api-keys", authMW(http.HandlerFunc(apiKeys.Create)))
	mux.Handle("DELETE /api/v1/api-keys/{id}", authMW(http.HandlerFunc(apiKeys.Delete)))

	// Admin routes (auth + admin check)
	mux.Handle("GET /api/v1/admin/stats", authMW(adminMW(http.HandlerFunc(admin.Stats))))
	mux.Handle("GET /api/v1/admin/users", authMW(adminMW(http.HandlerFunc(admin.ListUsers))))
	mux.Handle("PUT /api/v1/admin/users/{id}/plan", authMW(adminMW(http.HandlerFunc(admin.SetPlan))))
	mux.Handle("GET /api/v1/admin/waitlist", authMW(adminMW(http.HandlerFunc(admin.Waitlist))))

	// Waitlist (public)
	waitlist := NewWaitlistHandler(s)
	mux.HandleFunc("POST /api/v1/waitlist", waitlist.Join)

	// Heartbeat ping (public)
	mux.HandleFunc("GET /api/v1/heartbeat/{token}", heartbeat.PingGet)
	mux.HandleFunc("POST /api/v1/heartbeat/{token}", heartbeat.Ping)

	// Public status page (public)
	mux.HandleFunc("GET /status/{token}", statusPages.PublicView)
	mux.HandleFunc("POST /status/{token}", statusPages.PublicView)

	// Apply global middleware: logging -> CORS -> routes
	var handler http.Handler = mux
	handler = CORSMiddleware(handler)
	handler = LoggingMiddleware(handler)

	return handler
}
