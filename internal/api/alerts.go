package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/smtp"
	"time"

	"github.com/getpong/pong-backend-go/internal/alerter"
	"github.com/getpong/pong-backend-go/internal/config"
	"github.com/getpong/pong-backend-go/internal/model"
	"github.com/getpong/pong-backend-go/internal/store"
)

// AlertHandler handles alert contact CRUD endpoints.
type AlertHandler struct {
	store       *store.Store
	cfg         *config.Config
	verifiedTmpl *template.Template
}

// NewAlertHandler creates a new AlertHandler.
func NewAlertHandler(s *store.Store, cfg *config.Config) *AlertHandler {
	tmpl := template.Must(template.ParseFiles("templates/verified.html"))
	return &AlertHandler{store: s, cfg: cfg, verifiedTmpl: tmpl}
}

type createAlertContactRequest struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Name  string `json:"name"`
}

type updateAlertContactRequest struct {
	Type  *string `json:"type,omitempty"`
	Value *string `json:"value,omitempty"`
	Name  *string `json:"name,omitempty"`
}

var validAlertTypes = map[string]bool{
	"email":   true,
	"slack":   true,
	"webhook": true,
}

// ListContacts returns all alert contacts for the authenticated user.
func (h *AlertHandler) ListContacts(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())

	contacts, err := h.store.ListAlertContacts(r.Context(), userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list alert contacts")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{"alert_contacts": contacts})
}

// CreateContact adds a new alert contact for the authenticated user.
func (h *AlertHandler) CreateContact(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())

	var req createAlertContactRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Type == "" || req.Value == "" {
		respondError(w, http.StatusBadRequest, "type and value are required")
		return
	}
	if !validAlertTypes[req.Type] {
		respondError(w, http.StatusBadRequest, "type must be email, slack, or webhook")
		return
	}

	// Plan limit check.
	if h.cfg.EnforcePlanLimits {
		plan, _ := h.store.GetUserPlan(r.Context(), userID)
		limits := config.GetPlanLimits(plan)
		if limits.MaxContacts >= 0 {
			count, _ := h.store.CountAlertContacts(r.Context(), userID)
			if count >= limits.MaxContacts {
				respondError(w, http.StatusForbidden, fmt.Sprintf("alert contact limit reached (%d/%d on %s plan)", count, limits.MaxContacts, plan))
				return
			}
		}
	}

	contact := &model.AlertContact{
		UserID: userID,
		Type:   req.Type,
		Value:  req.Value,
		Name:   req.Name,
	}

	var verifyToken string
	if req.Type == "email" && h.cfg.RequireEmailVerification {
		b := make([]byte, 16)
		rand.Read(b)
		verifyToken = hex.EncodeToString(b)
	}

	created, err := h.store.CreateAlertContact(r.Context(), contact, verifyToken)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create alert contact")
		return
	}

	respondJSON(w, http.StatusCreated, created)
}

// UpdateContact modifies an existing alert contact for the authenticated user.
func (h *AlertHandler) UpdateContact(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())

	id, err := parseID(r, "id")
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	existing, err := h.store.GetAlertContact(r.Context(), id, userID)
	if err != nil {
		respondError(w, http.StatusNotFound, "alert contact not found")
		return
	}

	var req updateAlertContactRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	oldValue := existing.Value
	oldType := existing.Type

	if req.Type != nil {
		if !validAlertTypes[*req.Type] {
			respondError(w, http.StatusBadRequest, "type must be email, slack, or webhook")
			return
		}
		existing.Type = *req.Type
	}
	if req.Value != nil {
		existing.Value = *req.Value
	}
	if req.Name != nil {
		existing.Name = *req.Name
	}

	// Determine verification state.
	verified := 1
	verifyToken := ""
	emailChanged := existing.Type == "email" && (existing.Value != oldValue || oldType != "email")
	if emailChanged {
		// Email changed or type changed to email — reset verification.
		verified = 0
		b := make([]byte, 16)
		rand.Read(b)
		verifyToken = hex.EncodeToString(b)
		existing.Verified = false
	} else if existing.Type == "email" && !existing.Verified {
		verified = 0
	} else if existing.Type != "email" {
		// Slack/webhook are always verified.
		verified = 1
		existing.Verified = true
	}

	if err := h.store.UpdateAlertContact(r.Context(), existing, verified, verifyToken); err != nil {
		respondError(w, http.StatusNotFound, "alert contact not found")
		return
	}

	respondJSON(w, http.StatusOK, existing)
}

// DeleteContact removes an alert contact by ID for the authenticated user.
func (h *AlertHandler) DeleteContact(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())

	id, err := parseID(r, "id")
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.store.DeleteAlertContact(r.Context(), id, userID); err != nil {
		respondError(w, http.StatusNotFound, "alert contact not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// TestContact sends a test alert to a specific alert contact.
func (h *AlertHandler) TestContact(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())

	id, err := parseID(r, "id")
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	contacts, err := h.store.ListAlertContacts(r.Context(), userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list contacts")
		return
	}

	var contact *model.AlertContact
	for _, c := range contacts {
		if c.ID == id {
			contact = &c
			break
		}
	}
	if contact == nil {
		respondError(w, http.StatusNotFound, "alert contact not found")
		return
	}

	testEvent := model.StateChangeEvent{
		Monitor: model.Monitor{
			Name:   "Test Monitor",
			Target: "https://example.com",
		},
		OldStatus: "up",
		NewStatus: "down",
		Result: model.CheckResult{
			Status:    "down",
			Message:   "This is a test alert from Pong.",
			CheckedAt: time.Now(),
		},
	}

	var sendErr error
	switch contact.Type {
	case "email":
		sendErr = alerter.SendEmail(h.cfg, contact.Value, testEvent)
	case "slack":
		sendErr = alerter.SendSlack(r.Context(), contact.Value, testEvent)
	case "webhook":
		sendErr = alerter.SendWebhook(r.Context(), contact.Value, testEvent)
	default:
		respondError(w, http.StatusBadRequest, "unsupported contact type")
		return
	}

	if sendErr != nil {
		respondError(w, http.StatusBadGateway, "test alert failed: "+sendErr.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

// VerifyContact handles GET /api/v1/alert-contacts/verify/{token}. Public endpoint.
func (h *AlertHandler) VerifyContact(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}

	if err := h.store.VerifyAlertContact(r.Context(), token); err != nil {
		http.Error(w, "invalid or expired verification link", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.verifiedTmpl.ExecuteTemplate(w, "verified.html", map[string]string{
		"Title":   "Email Verified",
		"Message": "Your email address has been verified. You can close this page.",
	})
}

// ResendVerification handles POST /api/v1/alert-contacts/{id}/resend. Authenticated.
func (h *AlertHandler) ResendVerification(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())

	id, err := parseID(r, "id")
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	b := make([]byte, 16)
	rand.Read(b)
	token := hex.EncodeToString(b)

	email, err := h.store.ResendVerification(r.Context(), id, userID, token)
	if err != nil {
		respondError(w, http.StatusNotFound, "contact not found or already verified")
		return
	}

	go h.sendVerificationEmail(email, token)

	respondJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

func (h *AlertHandler) sendVerificationEmail(to, token string) {
	cfg := h.cfg
	if cfg.SMTPHost == "" {
		slog.Warn("SMTP not configured, skipping verification email", "to", to)
		return
	}

	from := cfg.SMTPFromNoreply
	if from == "" {
		from = cfg.SMTPFrom
	}

	verifyURL := fmt.Sprintf("%s/verify-email/%s", h.cfg.BaseURL, token)
	subject := "[Pong] Verify your email address"
	body := fmt.Sprintf(
		"Please verify your email address by clicking the link below:\n\n%s\n\nIf you did not create this alert contact, you can ignore this email.",
		verifyURL,
	)

	msg := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		from, to, subject, body,
	)

	addr := fmt.Sprintf("%s:%s", cfg.SMTPHost, cfg.SMTPPort)
	auth := smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)

	if err := smtp.SendMail(addr, auth, from, []string{to}, []byte(msg)); err != nil {
		slog.Error("failed to send verification email", "to", to, "error", err)
	}
}
