package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/getpong/pong-backend-go/internal/model"
	"github.com/getpong/pong-backend-go/internal/store"
)

// StatusPageHandler handles status page CRUD and public view endpoints.
type StatusPageHandler struct {
	store    *store.Store
	tmpl     *template.Template
	pwdTmpl  *template.Template
}

// NewStatusPageHandler creates a new StatusPageHandler and parses the templates.
func NewStatusPageHandler(s *store.Store) *StatusPageHandler {
	funcMap := template.FuncMap{
		"lastIdx": func(s []model.DailyUptime) int {
			return len(s) - 1
		},
	}
	tmpl := template.Must(template.New("status.html").Funcs(funcMap).ParseFiles("templates/status.html"))
	pwdTmpl := template.Must(template.ParseFiles("templates/password.html"))
	return &StatusPageHandler{store: s, tmpl: tmpl, pwdTmpl: pwdTmpl}
}

type createStatusPageRequest struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Password    *string `json:"password,omitempty"`
	MonitorIDs  []int64 `json:"monitor_ids,omitempty"`
}

type updateStatusPageRequest struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	Password    *string `json:"password,omitempty"` // empty string = remove password
	MonitorIDs  []int64 `json:"monitor_ids,omitempty"`
}

type statusPageData struct {
	Page     model.StatusPage
	Monitors []statusPageMonitor
}

type statusPageMonitor struct {
	Monitor       model.Monitor
	UptimePercent float64
	DailyUptime   []model.DailyUptime
}

type passwordPageData struct {
	Name  string
	Error string
}

// List returns all status pages for the authenticated user.
func (h *StatusPageHandler) List(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())

	pages, err := h.store.ListStatusPages(r.Context(), userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list status pages")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{"status_pages": pages})
}

// Create adds a new status page for the authenticated user.
func (h *StatusPageHandler) Create(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())

	var req createStatusPageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		respondError(w, http.StatusBadRequest, "name is required")
		return
	}

	var passwordHash string
	if req.Password != nil && *req.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to hash password")
			return
		}
		passwordHash = string(hash)
	}

	page := &model.StatusPage{
		UserID:       userID,
		Name:         req.Name,
		Description:  req.Description,
		PasswordHash: passwordHash,
		MonitorIDs:   req.MonitorIDs,
	}

	created, err := h.store.CreateStatusPage(r.Context(), page)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create status page")
		return
	}

	respondJSON(w, http.StatusCreated, created)
}

// Get returns a single status page by ID for the authenticated user.
func (h *StatusPageHandler) Get(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())

	id, err := parseID(r, "id")
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	page, err := h.store.GetStatusPage(r.Context(), id, userID)
	if err != nil {
		respondError(w, http.StatusNotFound, "status page not found")
		return
	}

	respondJSON(w, http.StatusOK, page)
}

// Update modifies an existing status page for the authenticated user.
func (h *StatusPageHandler) Update(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())

	id, err := parseID(r, "id")
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	existing, err := h.store.GetStatusPage(r.Context(), id, userID)
	if err != nil {
		respondError(w, http.StatusNotFound, "status page not found")
		return
	}

	var req updateStatusPageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Description != nil {
		existing.Description = *req.Description
	}
	if req.Password != nil {
		if *req.Password == "" {
			existing.PasswordHash = ""
		} else {
			hash, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
			if err != nil {
				respondError(w, http.StatusInternalServerError, "failed to hash password")
				return
			}
			existing.PasswordHash = string(hash)
		}
		existing.HasPassword = existing.PasswordHash != ""
	}
	if req.MonitorIDs != nil {
		existing.MonitorIDs = req.MonitorIDs
	}

	if err := h.store.UpdateStatusPage(r.Context(), existing); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update status page")
		return
	}

	respondJSON(w, http.StatusOK, existing)
}

// Delete removes a status page by ID for the authenticated user.
func (h *StatusPageHandler) Delete(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())

	id, err := parseID(r, "id")
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.store.DeleteStatusPage(r.Context(), id, userID); err != nil {
		respondError(w, http.StatusNotFound, "status page not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// cookieValue computes the session cookie value for a status page.
func cookieValue(token string, pageID int64) string {
	h := sha256.Sum256([]byte(token + ":" + strconv.FormatInt(pageID, 10)))
	return hex.EncodeToString(h[:])
}

// PublicView serves the HTML status page for a given token.
func (h *StatusPageHandler) PublicView(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if token == "" {
		http.NotFound(w, r)
		return
	}

	page, err := h.store.GetStatusPageByToken(r.Context(), token)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Password protection check.
	if page.PasswordHash != "" {
		cookieName := fmt.Sprintf("sp_%d", page.ID)
		expectedCookie := cookieValue(page.Token, page.ID)

		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				respondError(w, http.StatusBadRequest, "invalid form")
				return
			}
			password := r.FormValue("password")
			if err := bcrypt.CompareHashAndPassword([]byte(page.PasswordHash), []byte(password)); err != nil {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				h.pwdTmpl.ExecuteTemplate(w, "password.html", passwordPageData{
					Name:  page.Name,
					Error: "Incorrect password.",
				})
				return
			}
			// Correct password — set cookie and redirect.
			http.SetCookie(w, &http.Cookie{
				Name:     cookieName,
				Value:    expectedCookie,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				Expires:  time.Now().Add(24 * time.Hour),
			})
			http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
			return
		}

		// GET — check cookie.
		c, err := r.Cookie(cookieName)
		if err != nil || c.Value != expectedCookie {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			h.pwdTmpl.ExecuteTemplate(w, "password.html", passwordPageData{
				Name: page.Name,
			})
			return
		}
	}

	// Render the status page.
	monitors, err := h.store.GetStatusPageMonitors(r.Context(), page.ID)
	if err != nil {
		slog.Error("failed to get status page monitors", "token", token, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	data := statusPageData{
		Page:     *page,
		Monitors: make([]statusPageMonitor, 0, len(monitors)),
	}

	for _, mon := range monitors {
		uptime, err := h.store.GetUptimePercentage(r.Context(), mon.ID, page.UserID, 24)
		if err != nil {
			slog.Warn("failed to get uptime for monitor", "monitor_id", mon.ID, "error", err)
			uptime = 0
		}
		daily, err := h.store.GetDailyUptime(r.Context(), mon.ID, 90)
		if err != nil {
			slog.Warn("failed to get daily uptime for monitor", "monitor_id", mon.ID, "error", err)
			daily = nil
		}
		data.Monitors = append(data.Monitors, statusPageMonitor{
			Monitor:       mon,
			UptimePercent: uptime,
			DailyUptime:   daily,
		})
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.Execute(w, data); err != nil {
		slog.Error("failed to render status page template", "token", token, "error", err)
	}
}
