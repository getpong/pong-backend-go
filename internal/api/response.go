package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

func respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}

func parseID(r *http.Request, param string) (int64, error) {
	raw := r.PathValue(param)
	if raw == "" {
		return 0, fmt.Errorf("missing path parameter %q", param)
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %q: %w", param, err)
	}
	return id, nil
}
