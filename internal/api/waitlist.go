package api

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/getpong/pong-backend-go/internal/store"
)

var emailRegexp = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// WaitlistHandler handles the public waitlist signup endpoint.
type WaitlistHandler struct {
	store *store.Store
}

// NewWaitlistHandler creates a new WaitlistHandler.
func NewWaitlistHandler(s *store.Store) *WaitlistHandler {
	return &WaitlistHandler{store: s}
}

// Join handles POST /api/v1/waitlist. Public endpoint, no auth.
func (h *WaitlistHandler) Join(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if !emailRegexp.MatchString(req.Email) {
		respondError(w, http.StatusBadRequest, "invalid email address")
		return
	}

	if err := h.store.AddToWaitlist(r.Context(), req.Email); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to join waitlist")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
