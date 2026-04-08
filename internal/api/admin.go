package api

import (
	"encoding/json"
	"net/http"

	"github.com/getpong/pong-backend-go/internal/store"
)

var validPlans = map[string]bool{
	"free": true, "pro": true, "business": true, "selfhosted": true,
}

// AdminHandler handles admin-only endpoints.
type AdminHandler struct {
	store store.APIStore
}

// NewAdminHandler creates a new AdminHandler.
func NewAdminHandler(s store.APIStore) *AdminHandler {
	return &AdminHandler{store: s}
}

// Stats returns high-level platform stats.
func (h *AdminHandler) Stats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.store.UserStats(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to get stats")
		return
	}
	respondJSON(w, http.StatusOK, stats)
}

// ListUsers returns all users.
func (h *AdminHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.store.ListUsers(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list users")
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"users": users})
}

// SetPlan changes a user's subscription plan.
func (h *AdminHandler) SetPlan(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r, "id")
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req struct {
		Plan string `json:"plan"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !validPlans[req.Plan] {
		respondError(w, http.StatusBadRequest, "plan must be free, pro, business, or selfhosted")
		return
	}

	if err := h.store.SetUserPlan(r.Context(), id, req.Plan); err != nil {
		respondError(w, http.StatusNotFound, "user not found")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"plan": req.Plan})
}

// Waitlist returns all waitlist entries.
func (h *AdminHandler) Waitlist(w http.ResponseWriter, r *http.Request) {
	entries, err := h.store.ListWaitlist(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list waitlist")
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"waitlist": entries})
}
