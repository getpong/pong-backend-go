package store

import (
	"context"
	"time"

	"github.com/getpong/pong-backend-go/internal/model"
)

// CheckerStore is consumed by the scheduler and checker to read due monitors
// and persist check results. Extracting this interface allows swapping the
// storage backend (e.g. PostgreSQL) without changing the checker package.
type CheckerStore interface {
	GetDueMonitors(ctx context.Context) ([]model.Monitor, error)
	UpdateMonitorStatus(ctx context.Context, id int64, status string, lastCheckedAt time.Time) error
	InsertCheckResult(ctx context.Context, cr *model.CheckResult) error
	IncrementConsecutiveFails(ctx context.Context, monitorID int64) (int, error)
	ResetConsecutiveFails(ctx context.Context, monitorID int64) error
	UpdateSSLExpiry(ctx context.Context, monitorID int64, expiryAt time.Time) error
	DecryptMonitorAuth(m *model.Monitor) (string, error)
	SaveCheckResult(ctx context.Context, monitorID int64, result *model.CheckResult, status string, resetFails bool, newFailCount int) error
}

// AlerterStore is consumed by the alerter to fetch contacts and log alerts.
type AlerterStore interface {
	GetAlertContactsForMonitor(ctx context.Context, monitorID int64) ([]model.AlertContact, error)
	InsertAlertLog(ctx context.Context, al *model.AlertLog) error
}

// PrunerStore is consumed by the pruner to delete old data.
type PrunerStore interface {
	PruneCheckResults(ctx context.Context, retentionDays int) (int64, error)
	PruneAlertLogs(ctx context.Context, retentionDays int) (int64, error)
}

// APIStore is consumed by the API handlers and middleware. It covers all
// CRUD operations exposed through the REST API.
type APIStore interface {
	// Users
	EnsureUser(ctx context.Context, oauthSub string, email string) (int64, error)
	GetUserByID(ctx context.Context, id int64) (*model.User, error)
	GetUserIDByAPIKey(ctx context.Context, key string) (int64, error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
	GetUserPlan(ctx context.Context, userID int64) (string, error)

	// Admin
	ListUsers(ctx context.Context) ([]model.User, error)
	SetUserPlan(ctx context.Context, userID int64, plan string) error
	UserStats(ctx context.Context) (map[string]int64, error)
	ListWaitlist(ctx context.Context) ([]map[string]string, error)

	// Monitors
	ListMonitors(ctx context.Context, userID int64) ([]model.Monitor, error)
	GetMonitor(ctx context.Context, id, userID int64) (*model.Monitor, error)
	CreateMonitor(ctx context.Context, m *model.Monitor) (*model.Monitor, error)
	UpdateMonitor(ctx context.Context, m *model.Monitor) error
	DeleteMonitor(ctx context.Context, id, userID int64) error
	SetMonitorEnabled(ctx context.Context, id, userID int64, enabled bool) error
	CountMonitors(ctx context.Context, userID int64) (int, error)

	// Check results & uptime
	ListCheckResults(ctx context.Context, monitorID, userID int64, limit, offset int) ([]model.CheckResult, int, error)
	GetUptimePercentage(ctx context.Context, monitorID, userID int64, hours int) (float64, error)
	GetDailyUptime(ctx context.Context, monitorID int64, days int) ([]model.DailyUptime, error)

	// Heartbeat
	GetMonitorByHeartbeatToken(ctx context.Context, token string) (*model.Monitor, error)
	UpdateHeartbeatPing(ctx context.Context, token string) (int64, error)
	UpdateMonitorStatus(ctx context.Context, id int64, status string, lastCheckedAt time.Time) error
	ResetConsecutiveFails(ctx context.Context, monitorID int64) error
	InsertCheckResult(ctx context.Context, cr *model.CheckResult) error

	// Alert contacts
	ListAlertContacts(ctx context.Context, userID int64) ([]model.AlertContact, error)
	GetAlertContact(ctx context.Context, id, userID int64) (*model.AlertContact, error)
	CreateAlertContact(ctx context.Context, ac *model.AlertContact, verifyToken string) (*model.AlertContact, error)
	UpdateAlertContact(ctx context.Context, ac *model.AlertContact, verified int, verifyToken string) error
	DeleteAlertContact(ctx context.Context, id, userID int64) error
	VerifyAlertContact(ctx context.Context, token string) error
	ResendVerification(ctx context.Context, id, userID int64, token string) (string, error)
	CountAlertContacts(ctx context.Context, userID int64) (int, error)
	VerifyAlertContactOwnership(ctx context.Context, userID int64, contactIDs []int64) (bool, error)

	// Status pages
	ListStatusPages(ctx context.Context, userID int64) ([]model.StatusPage, error)
	GetStatusPage(ctx context.Context, id, userID int64) (*model.StatusPage, error)
	CreateStatusPage(ctx context.Context, sp *model.StatusPage) (*model.StatusPage, error)
	UpdateStatusPage(ctx context.Context, sp *model.StatusPage) error
	DeleteStatusPage(ctx context.Context, id, userID int64) error
	GetStatusPageByToken(ctx context.Context, token string) (*model.StatusPage, error)
	GetStatusPageMonitors(ctx context.Context, statusPageID int64) ([]model.Monitor, error)
	VerifyMonitorOwnership(ctx context.Context, userID int64, monitorIDs []int64) (bool, error)

	// API keys
	ListAPIKeys(ctx context.Context, userID int64) ([]model.APIKey, error)
	CreateAPIKey(ctx context.Context, userID int64, name, prefix, keyHash string) (*model.APIKey, error)
	DeleteAPIKey(ctx context.Context, id, userID int64) error

	// Waitlist
	AddToWaitlist(ctx context.Context, email string) error
}
