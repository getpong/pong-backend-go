package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/getpong/pong-backend-go/internal/model"
	"github.com/getpong/pong-backend-go/internal/store"
)

type APIKeyHandler struct {
	store *store.Store
}

func NewAPIKeyHandler(s *store.Store) *APIKeyHandler {
	return &APIKeyHandler{store: s}
}

// List returns all API keys for the authenticated user (no raw keys).
func (h *APIKeyHandler) List(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())

	keys, err := h.store.ListAPIKeys(r.Context(), userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list api keys")
		return
	}
	if keys == nil {
		keys = []model.APIKey{}
	}

	respondJSON(w, http.StatusOK, map[string]any{"api_keys": keys})
}

// Create generates a new API key.
func (h *APIKeyHandler) Create(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())

	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Name == "" {
		respondError(w, http.StatusBadRequest, "name is required")
		return
	}

	// Generate: "pong_" + 32 random hex chars = 40 chars total.
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to generate api key")
		return
	}
	rawKey := "pong_" + hex.EncodeToString(randomBytes)
	prefix := rawKey[:8]

	hash := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(hash[:])

	apiKey, err := h.store.CreateAPIKey(r.Context(), userID, body.Name, prefix, keyHash)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create api key")
		return
	}

	respondJSON(w, http.StatusCreated, model.APIKeyCreated{
		APIKey: *apiKey,
		Key:    rawKey,
	})
}

// Delete removes an API key.
func (h *APIKeyHandler) Delete(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())

	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid id")
		return
	}

	if err := h.store.DeleteAPIKey(r.Context(), id, userID); err != nil {
		respondError(w, http.StatusNotFound, fmt.Sprintf("api key %d not found", id))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
