package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/getpong/pong-backend-go/internal/config"
	"github.com/getpong/pong-backend-go/internal/model"
	"github.com/getpong/pong-backend-go/internal/store"
)

var validMonitorTypes = map[string]bool{
	"http": true, "keyword": true, "ssl": true, "heartbeat": true,
	"port": true,
}

// MonitorHandler handles monitor CRUD and related endpoints.
type MonitorHandler struct {
	store *store.Store
	cfg   *config.Config
}

// NewMonitorHandler creates a new MonitorHandler.
func NewMonitorHandler(s *store.Store, cfg *config.Config) *MonitorHandler {
	return &MonitorHandler{store: s, cfg: cfg}
}

type createMonitorRequest struct {
	Name              string  `json:"name"`
	Type              string  `json:"type"`
	Target            string  `json:"target"`
	IntervalSecs      *int    `json:"interval_secs"`
	TimeoutSecs       *int    `json:"timeout_secs"`
	Keyword           string  `json:"keyword,omitempty"`
	KeywordType       string  `json:"keyword_type,omitempty"`
	KeywordMatch      string  `json:"keyword_match,omitempty"`
	ExpectedStatus    *int    `json:"expected_status"`
	LatencyWarnMs     int     `json:"latency_warn_ms,omitempty"`
	ConfirmationCount *int    `json:"confirmation_count"`
	HeartbeatSecret   string  `json:"heartbeat_secret,omitempty"`
	SSLWarnDays       *int    `json:"ssl_warn_days"`
	AlertContactIDs   []int64 `json:"alert_contact_ids,omitempty"`
	HttpAuthType      string  `json:"http_auth_type,omitempty"`
	HttpAuthUsername  string  `json:"http_auth_username,omitempty"`
	HttpAuthPassword  string  `json:"http_auth_password,omitempty"`
	HttpAuthHeader    string  `json:"http_auth_header,omitempty"`
	HttpAuthValue     string  `json:"http_auth_value,omitempty"`
}

type updateMonitorRequest struct {
	Name              *string `json:"name,omitempty"`
	Type              *string `json:"type,omitempty"`
	Target            *string `json:"target,omitempty"`
	IntervalSecs      *int    `json:"interval_secs,omitempty"`
	TimeoutSecs       *int    `json:"timeout_secs,omitempty"`
	Keyword           *string `json:"keyword,omitempty"`
	KeywordType       *string `json:"keyword_type,omitempty"`
	KeywordMatch      *string `json:"keyword_match,omitempty"`
	ExpectedStatus    *int    `json:"expected_status,omitempty"`
	LatencyWarnMs     *int    `json:"latency_warn_ms,omitempty"`
	ConfirmationCount *int    `json:"confirmation_count,omitempty"`
	HeartbeatSecret   *string `json:"heartbeat_secret,omitempty"`
	SSLWarnDays       *int    `json:"ssl_warn_days,omitempty"`
	AlertContactIDs   []int64 `json:"alert_contact_ids,omitempty"`
	HttpAuthType      *string `json:"http_auth_type,omitempty"`
	HttpAuthUsername  *string `json:"http_auth_username,omitempty"`
	HttpAuthPassword  *string `json:"http_auth_password,omitempty"`
	HttpAuthHeader    *string `json:"http_auth_header,omitempty"`
	HttpAuthValue     *string `json:"http_auth_value,omitempty"`
}

var validHttpAuthTypes = map[string]bool{
	"none": true, "basic": true, "header": true,
}

// List returns all monitors for the authenticated user.
func (h *MonitorHandler) List(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())

	monitors, err := h.store.ListMonitors(r.Context(), userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list monitors")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{"monitors": monitors})
}

// Create adds a new monitor for the authenticated user.
func (h *MonitorHandler) Create(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())

	var req createMonitorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" || req.Type == "" {
		respondError(w, http.StatusBadRequest, "name and type are required")
		return
	}
	if !validMonitorTypes[req.Type] {
		respondError(w, http.StatusBadRequest, "invalid monitor type")
		return
	}
	if req.Type != "heartbeat" && req.Target == "" {
		respondError(w, http.StatusBadRequest, "target is required for this monitor type")
		return
	}

	intervalSecs := 300
	if req.IntervalSecs != nil {
		intervalSecs = *req.IntervalSecs
	}

	// Plan limit checks.
	if h.cfg.EnforcePlanLimits {
		plan, _ := h.store.GetUserPlan(r.Context(), userID)
		limits := config.GetPlanLimits(plan)

		if limits.MaxMonitors >= 0 {
			count, _ := h.store.CountMonitors(r.Context(), userID)
			if count >= limits.MaxMonitors {
				respondError(w, http.StatusForbidden, fmt.Sprintf("monitor limit reached (%d/%d on %s plan)", count, limits.MaxMonitors, plan))
				return
			}
		}

		if intervalSecs < limits.MinInterval {
			respondError(w, http.StatusForbidden, fmt.Sprintf("minimum interval is %ds on %s plan", limits.MinInterval, plan))
			return
		}
	}
	timeoutSecs := 30
	if req.TimeoutSecs != nil {
		timeoutSecs = *req.TimeoutSecs
	}
	expectedStatus := 200
	if req.ExpectedStatus != nil {
		expectedStatus = *req.ExpectedStatus
	}
	confirmationCount := 1
	if req.ConfirmationCount != nil && *req.ConfirmationCount > 0 {
		confirmationCount = *req.ConfirmationCount
	}
	sslWarnDays := 30
	if req.SSLWarnDays != nil && *req.SSLWarnDays > 0 {
		sslWarnDays = *req.SSLWarnDays
	}

	var heartbeatToken string
	if req.Type == "heartbeat" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			respondError(w, http.StatusInternalServerError, "failed to generate heartbeat token")
			return
		}
		heartbeatToken = hex.EncodeToString(b)
	}

	// Build HTTP auth blob if configured.
	httpAuthType := "none"
	httpAuth := ""
	if req.HttpAuthType != "" && req.HttpAuthType != "none" {
		if !validHttpAuthTypes[req.HttpAuthType] {
			respondError(w, http.StatusBadRequest, "http_auth_type must be none, basic, or header")
			return
		}
		if req.Type != "http" && req.Type != "keyword" {
			respondError(w, http.StatusBadRequest, "HTTP authentication is only supported for http and keyword monitors")
			return
		}
		if !h.cfg.EncryptionEnabled() {
			respondError(w, http.StatusBadRequest, "encryption not configured; cannot use HTTP authentication")
			return
		}
		switch req.HttpAuthType {
		case "basic":
			if req.HttpAuthUsername == "" || req.HttpAuthPassword == "" {
				respondError(w, http.StatusBadRequest, "username and password are required for basic auth")
				return
			}
			blob, _ := json.Marshal(model.HttpAuthBasic{Type: "basic", Username: req.HttpAuthUsername, Password: req.HttpAuthPassword})
			httpAuth = string(blob)
		case "header":
			if req.HttpAuthHeader == "" || req.HttpAuthValue == "" {
				respondError(w, http.StatusBadRequest, "header name and value are required for header auth")
				return
			}
			blob, _ := json.Marshal(model.HttpAuthHeader{Type: "header", Header: req.HttpAuthHeader, Value: req.HttpAuthValue})
			httpAuth = string(blob)
		}
		httpAuthType = req.HttpAuthType
	}

	mon := &model.Monitor{
		UserID:            userID,
		Name:              req.Name,
		Type:              req.Type,
		Target:            req.Target,
		IntervalSecs:      intervalSecs,
		TimeoutSecs:       timeoutSecs,
		Keyword:           req.Keyword,
		KeywordType:       req.KeywordType,
		KeywordMatch:      req.KeywordMatch,
		ExpectedStatus:    expectedStatus,
		LatencyWarnMs:     req.LatencyWarnMs,
		ConfirmationCount: confirmationCount,
		SSLWarnDays:       sslWarnDays,
		HeartbeatToken:    heartbeatToken,
		HeartbeatSecret:   req.HeartbeatSecret,
		HttpAuthType:      httpAuthType,
		HttpAuth:          httpAuth,
		Enabled:           true,
		Status:            "unknown",
		AlertContactIDs:   req.AlertContactIDs,
	}

	if len(req.AlertContactIDs) > 0 {
		owned, err := h.store.VerifyAlertContactOwnership(r.Context(), userID, req.AlertContactIDs)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to verify alert contacts")
			return
		}
		if !owned {
			respondError(w, http.StatusNotFound, "one or more alert contacts not found")
			return
		}
	}

	created, err := h.store.CreateMonitor(r.Context(), mon)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create monitor")
		return
	}

	respondJSON(w, http.StatusCreated, created)
}

// Get returns a single monitor by ID for the authenticated user.
func (h *MonitorHandler) Get(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())

	id, err := parseID(r, "id")
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	mon, err := h.store.GetMonitor(r.Context(), id, userID)
	if err != nil {
		respondError(w, http.StatusNotFound, "monitor not found")
		return
	}

	respondJSON(w, http.StatusOK, mon)
}

// Update modifies an existing monitor for the authenticated user.
func (h *MonitorHandler) Update(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())

	id, err := parseID(r, "id")
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	existing, err := h.store.GetMonitor(r.Context(), id, userID)
	if err != nil {
		respondError(w, http.StatusNotFound, "monitor not found")
		return
	}

	var req updateMonitorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Type != nil {
		existing.Type = *req.Type
	}
	if req.Target != nil {
		existing.Target = *req.Target
	}
	if req.IntervalSecs != nil {
		existing.IntervalSecs = *req.IntervalSecs
	}
	if req.TimeoutSecs != nil {
		existing.TimeoutSecs = *req.TimeoutSecs
	}
	if req.Keyword != nil {
		existing.Keyword = *req.Keyword
	}
	if req.KeywordType != nil {
		existing.KeywordType = *req.KeywordType
	}
	if req.KeywordMatch != nil {
		existing.KeywordMatch = *req.KeywordMatch
	}
	if req.ExpectedStatus != nil {
		existing.ExpectedStatus = *req.ExpectedStatus
	}
	if req.LatencyWarnMs != nil {
		existing.LatencyWarnMs = *req.LatencyWarnMs
	}
	if req.ConfirmationCount != nil {
		existing.ConfirmationCount = *req.ConfirmationCount
	}
	if req.HeartbeatSecret != nil {
		existing.HeartbeatSecret = *req.HeartbeatSecret
	}
	if req.SSLWarnDays != nil {
		existing.SSLWarnDays = *req.SSLWarnDays
	}
	if req.HttpAuthType != nil {
		authType := *req.HttpAuthType
		if !validHttpAuthTypes[authType] {
			respondError(w, http.StatusBadRequest, "http_auth_type must be none, basic, or header")
			return
		}
		if authType == "none" {
			existing.HttpAuthType = "none"
			existing.HttpAuth = ""
			existing.HttpAuthConfigured = false
		} else {
			if existing.Type != "http" && existing.Type != "keyword" {
				respondError(w, http.StatusBadRequest, "HTTP authentication is only supported for http and keyword monitors")
				return
			}
			if !h.cfg.EncryptionEnabled() {
				respondError(w, http.StatusBadRequest, "encryption not configured; cannot use HTTP authentication")
				return
			}
			switch authType {
			case "basic":
				username := ""
				password := ""
				if req.HttpAuthUsername != nil {
					username = *req.HttpAuthUsername
				}
				if req.HttpAuthPassword != nil {
					password = *req.HttpAuthPassword
				}
				if username == "" || password == "" {
					respondError(w, http.StatusBadRequest, "username and password are required for basic auth")
					return
				}
				blob, _ := json.Marshal(model.HttpAuthBasic{Type: "basic", Username: username, Password: password})
				existing.HttpAuth = string(blob)
			case "header":
				header := ""
				value := ""
				if req.HttpAuthHeader != nil {
					header = *req.HttpAuthHeader
				}
				if req.HttpAuthValue != nil {
					value = *req.HttpAuthValue
				}
				if header == "" || value == "" {
					respondError(w, http.StatusBadRequest, "header name and value are required for header auth")
					return
				}
				blob, _ := json.Marshal(model.HttpAuthHeader{Type: "header", Header: header, Value: value})
				existing.HttpAuth = string(blob)
			}
			existing.HttpAuthType = authType
			existing.HttpAuthConfigured = true
		}
	}

	if req.AlertContactIDs != nil {
		if len(req.AlertContactIDs) > 0 {
			owned, err := h.store.VerifyAlertContactOwnership(r.Context(), userID, req.AlertContactIDs)
			if err != nil {
				respondError(w, http.StatusInternalServerError, "failed to verify alert contacts")
				return
			}
			if !owned {
				respondError(w, http.StatusNotFound, "one or more alert contacts not found")
				return
			}
		}
		existing.AlertContactIDs = req.AlertContactIDs
	}

	// Plan limit check on interval.
	if h.cfg.EnforcePlanLimits && req.IntervalSecs != nil {
		plan, _ := h.store.GetUserPlan(r.Context(), userID)
		limits := config.GetPlanLimits(plan)
		if existing.IntervalSecs < limits.MinInterval {
			respondError(w, http.StatusForbidden, fmt.Sprintf("minimum interval is %ds on %s plan", limits.MinInterval, plan))
			return
		}
	}

	if err := h.store.UpdateMonitor(r.Context(), existing); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update monitor")
		return
	}

	respondJSON(w, http.StatusOK, existing)
}

// Delete removes a monitor by ID for the authenticated user.
func (h *MonitorHandler) Delete(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())

	id, err := parseID(r, "id")
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.store.DeleteMonitor(r.Context(), id, userID); err != nil {
		respondError(w, http.StatusNotFound, "monitor not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Pause disables a monitor.
func (h *MonitorHandler) Pause(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())

	id, err := parseID(r, "id")
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.store.SetMonitorEnabled(r.Context(), id, userID, false); err != nil {
		respondError(w, http.StatusNotFound, "monitor not found")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{"enabled": false})
}

// Resume enables a monitor.
func (h *MonitorHandler) Resume(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())

	id, err := parseID(r, "id")
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.store.SetMonitorEnabled(r.Context(), id, userID, true); err != nil {
		respondError(w, http.StatusNotFound, "monitor not found")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{"enabled": true})
}

// Results returns paginated check results for a monitor.
func (h *MonitorHandler) Results(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())

	id, err := parseID(r, "id")
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	limit := queryInt(r, "limit", 50)
	offset := queryInt(r, "offset", 0)

	results, total, err := h.store.ListCheckResults(r.Context(), id, userID, limit, offset)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list check results")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"results": results,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

// Uptime returns the uptime percentage for a monitor.
func (h *MonitorHandler) Uptime(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())

	id, err := parseID(r, "id")
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	hours := queryInt(r, "hours", 24)

	pct, err := h.store.GetUptimePercentage(r.Context(), id, userID, hours)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to calculate uptime")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"monitor_id": id,
		"hours":      hours,
		"percentage": pct,
	})
}

// DailyUptime returns per-day uptime percentages for a monitor.
func (h *MonitorHandler) DailyUptime(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())

	id, err := parseID(r, "id")
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Verify ownership.
	_, err = h.store.GetMonitor(r.Context(), id, userID)
	if err != nil {
		respondError(w, http.StatusNotFound, "monitor not found")
		return
	}

	days := queryInt(r, "days", 90)
	if days > 365 {
		days = 365
	}

	data, err := h.store.GetDailyUptime(r.Context(), id, days)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to get daily uptime")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{"monitor_id": id, "days": days, "daily": data})
}

// queryInt reads an integer query parameter with a default value.
func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
