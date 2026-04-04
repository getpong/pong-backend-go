package model

import "time"

type User struct {
	ID              int64     `json:"id"`
	OAuthSub        string    `json:"oauth_sub"`
	Email           string    `json:"email"`
	IsAdmin         bool      `json:"is_admin"`
	Plan            string    `json:"plan"`
	TotalMonitors   int       `json:"total_monitors,omitempty"`
	ActiveMonitors  int       `json:"active_monitors,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type Monitor struct {
	ID              int64      `json:"id"`
	UserID          int64      `json:"user_id"`
	Name            string     `json:"name"`
	Type            string     `json:"type"`
	Target          string     `json:"target"`
	IntervalSecs    int        `json:"interval_secs"`
	TimeoutSecs     int        `json:"timeout_secs"`
	Keyword         string     `json:"keyword,omitempty"`
	KeywordType     string     `json:"keyword_type,omitempty"`
	KeywordMatch    string     `json:"keyword_match,omitempty"`
	ExpectedStatus  int        `json:"expected_status,omitempty"`
	LatencyWarnMs     int        `json:"latency_warn_ms,omitempty"`
	ConfirmationCount int        `json:"confirmation_count"`
	ConsecutiveFails  int        `json:"consecutive_fails"`
	HeartbeatToken    string     `json:"heartbeat_token,omitempty"`
	HeartbeatSecret   string     `json:"heartbeat_secret,omitempty"`
	HeartbeatLastPing *time.Time `json:"heartbeat_last_ping,omitempty"`
	SSLWarnDays       int        `json:"ssl_warn_days,omitempty"`
	SSLExpiryAt       *time.Time `json:"ssl_expiry_at,omitempty"`
	Enabled           bool       `json:"enabled"`
	Status          string     `json:"status"`
	LastCheckedAt   *time.Time `json:"last_checked_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	AlertContactIDs []int64    `json:"alert_contact_ids,omitempty"`
}

type StatusPage struct {
	ID           int64     `json:"id"`
	UserID       int64     `json:"user_id"`
	Name         string    `json:"name"`
	Token        string    `json:"token"`
	Description  string    `json:"description"`
	HasPassword  bool      `json:"has_password"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	MonitorIDs   []int64   `json:"monitor_ids,omitempty"`
}

type CheckResult struct {
	ID         int64     `json:"id"`
	MonitorID  int64     `json:"monitor_id"`
	Status     string    `json:"status"`
	LatencyMs  int       `json:"latency_ms"`
	StatusCode int       `json:"status_code,omitempty"`
	Message    string    `json:"message,omitempty"`
	Region     string    `json:"region"`
	CheckedAt  time.Time `json:"checked_at"`
}

type AlertContact struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	Name      string    `json:"name"`
	Verified  bool      `json:"verified"`
	CreatedAt time.Time `json:"created_at"`
}

type AlertLog struct {
	ID             int64     `json:"id"`
	MonitorID      int64     `json:"monitor_id"`
	AlertContactID int64     `json:"alert_contact_id"`
	Type           string    `json:"type"`
	Message        string    `json:"message"`
	SentAt         time.Time `json:"sent_at"`
}

type StateChangeEvent struct {
	Monitor   Monitor
	OldStatus string
	NewStatus string
	Result    CheckResult
}

type DailyUptime struct {
	Date        string  `json:"date"`         // "2026-03-29"
	Percentage  float64 `json:"percentage"`
	TotalChecks int     `json:"total_checks"`
}

type APIKey struct {
	ID         int64      `json:"id"`
	UserID     int64      `json:"user_id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// APIKeyCreated is returned only once when creating a key — includes the raw key.
type APIKeyCreated struct {
	APIKey
	Key string `json:"key"`
}
