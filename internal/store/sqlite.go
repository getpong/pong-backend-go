package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/getpong/pong-backend-go/internal/crypto"
	"github.com/getpong/pong-backend-go/internal/model"

	_ "modernc.org/sqlite"
)

const timeFormat = "2006-01-02T15:04:05Z"

const monitorColumns = `id, user_id, name, type, target, interval_secs, timeout_secs,
	keyword, keyword_type, keyword_match, expected_status, latency_warn_ms,
	confirmation_count, consecutive_fails, heartbeat_token, heartbeat_secret, heartbeat_last_ping,
	ssl_warn_days, ssl_expiry_at, protocol, http_auth_type, http_auth,
	dns_record_type, dns_expected_value, dns_resolver,
	enabled, status, last_checked_at, created_at, updated_at`

// SQLiteStore is the SQLite-backed implementation of the store interfaces.
type SQLiteStore struct {
	db            *sql.DB
	encryptionKey string
}

func NewSQLite(dbPath string, encryptionKey string) (*SQLiteStore, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}

	dsn := dbPath + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return &SQLiteStore{db: db, encryptionKey: encryptionKey}, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// DB returns the underlying *sql.DB for direct queries (e.g. benchmarks).
func (s *SQLiteStore) DB() *sql.DB {
	return s.db
}

// BootstrapAdminKey ensures an admin user and API key exist for the given raw key.
// Used on startup when ADMIN_API_KEY is set. Idempotent — skips if the key already exists.
func (s *SQLiteStore) BootstrapAdminKey(ctx context.Context, rawKey string) error {
	keyHash := sha256Hex(rawKey)
	prefix := rawKey[:8]

	// Create or get admin user.
	now := time.Now().UTC().Format(timeFormat)
	var userID int64
	err := s.db.QueryRowContext(ctx, "SELECT id FROM users WHERE email = 'admin'").Scan(&userID)
	if err != nil {
		res, err := s.db.ExecContext(ctx,
			"INSERT INTO users (oauth_sub, email, is_admin, plan, created_at, updated_at) VALUES (?, ?, 1, 'selfhosted', ?, ?)",
			"local|admin", "admin", now, now,
		)
		if err != nil {
			return fmt.Errorf("create admin user: %w", err)
		}
		userID, _ = res.LastInsertId()
	} else {
		s.db.ExecContext(ctx, "UPDATE users SET is_admin = 1 WHERE id = ?", userID)
	}

	// Check if key already exists.
	var exists int
	s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM api_keys WHERE key_hash = ?", keyHash).Scan(&exists)
	if exists > 0 {
		return nil
	}

	// Remove any previous bootstrap key, then insert the new one.
	s.db.ExecContext(ctx, "DELETE FROM api_keys WHERE user_id = ? AND name = 'Admin Bootstrap Key'", userID)

	_, err = s.db.ExecContext(ctx,
		"INSERT INTO api_keys (user_id, name, prefix, key_hash, created_at) VALUES (?, ?, ?, ?, ?)",
		userID, "Admin Bootstrap Key", prefix, keyHash, now,
	)
	if err != nil {
		return fmt.Errorf("create admin api key: %w", err)
	}

	return nil
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// Migrate reads .sql files from migrationsDir and executes unapplied ones.
func (s *SQLiteStore) Migrate(migrationsDir string) error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		filename TEXT PRIMARY KEY,
		applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
	)`)
	if err != nil {
		return fmt.Errorf("create schema_migrations table: %w", err)
	}

	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		return fmt.Errorf("read migrations directory: %w", err)
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	// Fresh install detection: no applied migrations.
	// Run only the baseline (first file) which contains the current schema,
	// and record all other migrations as already applied — self-hosters get
	// a clean DB without running historical fixup migrations.
	var migCount int
	s.db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&migCount)
	if migCount == 0 && len(files) > 0 {
		baseline := files[0]
		content, err := os.ReadFile(filepath.Join(migrationsDir, baseline))
		if err != nil {
			return fmt.Errorf("read baseline %s: %w", baseline, err)
		}
		tx, err := s.db.Begin()
		if err != nil {
			return fmt.Errorf("begin baseline tx: %w", err)
		}
		if _, err := tx.Exec(string(content)); err != nil {
			tx.Rollback()
			return fmt.Errorf("execute baseline %s: %w", baseline, err)
		}
		for _, name := range files {
			if _, err := tx.Exec("INSERT INTO schema_migrations (filename) VALUES (?)", name); err != nil {
				tx.Rollback()
				return fmt.Errorf("record baseline migration %s: %w", name, err)
			}
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit baseline: %w", err)
		}
		return nil
	}

	for _, name := range files {
		var count int
		err := s.db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE filename = ?", name).Scan(&count)
		if err != nil {
			return fmt.Errorf("check migration %s: %w", name, err)
		}
		if count > 0 {
			continue
		}

		content, err := os.ReadFile(filepath.Join(migrationsDir, name))
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}

		tx, err := s.db.Begin()
		if err != nil {
			return fmt.Errorf("begin transaction for %s: %w", name, err)
		}

		if _, err := tx.Exec(string(content)); err != nil {
			tx.Rollback()
			return fmt.Errorf("execute migration %s: %w", name, err)
		}

		if _, err := tx.Exec("INSERT INTO schema_migrations (filename) VALUES (?)", name); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration %s: %w", name, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", name, err)
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

// EnsureUser returns the local user ID for an Auth0 subject, creating the user
// on first encounter. This implements the UserProvisioner interface.
func (s *SQLiteStore) EnsureUser(ctx context.Context, auth0Sub string, email string) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx,
		"SELECT id FROM users WHERE oauth_sub = ?", auth0Sub,
	).Scan(&id)
	if err == nil {
		// Update email if provided and changed.
		if email != "" {
			s.db.ExecContext(ctx,
				"UPDATE users SET email = ?, updated_at = ? WHERE id = ? AND email != ?",
				email, time.Now().UTC().Format(timeFormat), id, email,
			)
		}
		return id, nil
	}

	now := time.Now().UTC().Format(timeFormat)
	res, err := s.db.ExecContext(ctx,
		"INSERT INTO users (oauth_sub, email, created_at, updated_at) VALUES (?, ?, ?, ?)",
		auth0Sub, email, now, now,
	)
	if err != nil {
		// Handle race condition: another request may have inserted concurrently.
		err2 := s.db.QueryRowContext(ctx,
			"SELECT id FROM users WHERE oauth_sub = ?", auth0Sub,
		).Scan(&id)
		if err2 == nil {
			return id, nil
		}
		return 0, fmt.Errorf("insert user: %w", err)
	}

	return res.LastInsertId()
}

func (s *SQLiteStore) GetUserByID(ctx context.Context, id int64) (*model.User, error) {
	var u model.User
	var isAdmin int
	var createdAt, updatedAt string
	err := s.db.QueryRowContext(ctx,
		"SELECT id, oauth_sub, email, is_admin, plan, created_at, updated_at FROM users WHERE id = ?", id,
	).Scan(&u.ID, &u.OAuthSub, &u.Email, &isAdmin, &u.Plan, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	u.IsAdmin = isAdmin == 1
	u.CreatedAt, _ = time.Parse(timeFormat, createdAt)
	u.UpdatedAt, _ = time.Parse(timeFormat, updatedAt)
	return &u, nil
}

// IsAdmin returns true if the user with the given ID has admin privileges.
func (s *SQLiteStore) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	var isAdmin int
	err := s.db.QueryRowContext(ctx,
		"SELECT is_admin FROM users WHERE id = ?", userID,
	).Scan(&isAdmin)
	if err != nil {
		return false, err
	}
	return isAdmin == 1, nil
}

// ListUsers returns all users with monitor counts.
func (s *SQLiteStore) ListUsers(ctx context.Context) ([]model.User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT u.id, u.oauth_sub, u.email, u.is_admin, u.plan, u.created_at, u.updated_at,
			COUNT(m.id) AS total_monitors,
			SUM(CASE WHEN m.enabled = 1 THEN 1 ELSE 0 END) AS active_monitors
		FROM users u
		LEFT JOIN monitors m ON m.user_id = u.id
		GROUP BY u.id
		ORDER BY u.id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []model.User
	for rows.Next() {
		var u model.User
		var isAdmin int
		var createdAt, updatedAt string
		if err := rows.Scan(&u.ID, &u.OAuthSub, &u.Email, &isAdmin, &u.Plan, &createdAt, &updatedAt, &u.TotalMonitors, &u.ActiveMonitors); err != nil {
			return nil, err
		}
		u.IsAdmin = isAdmin == 1
		u.CreatedAt, _ = time.Parse(timeFormat, createdAt)
		u.UpdatedAt, _ = time.Parse(timeFormat, updatedAt)
		users = append(users, u)
	}
	return users, rows.Err()
}

// SetUserPlan updates a user's subscription plan.
func (s *SQLiteStore) SetUserPlan(ctx context.Context, userID int64, plan string) error {
	now := time.Now().UTC().Format(timeFormat)
	res, err := s.db.ExecContext(ctx,
		"UPDATE users SET plan = ?, updated_at = ? WHERE id = ?",
		plan, now, userID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ListWaitlist returns all waitlist entries.
func (s *SQLiteStore) ListWaitlist(ctx context.Context) ([]map[string]string, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, email, created_at FROM waitlist ORDER BY id DESC",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []map[string]string
	for rows.Next() {
		var id int64
		var email, createdAt string
		if err := rows.Scan(&id, &email, &createdAt); err != nil {
			return nil, err
		}
		entries = append(entries, map[string]string{
			"id":         fmt.Sprintf("%d", id),
			"email":      email,
			"created_at": createdAt,
		})
	}
	return entries, rows.Err()
}

// UserStats returns summary counts for admin dashboard.
func (s *SQLiteStore) UserStats(ctx context.Context) (map[string]int64, error) {
	var totalUsers, totalMonitors, activeMonitors, waitlistCount int64
	s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&totalUsers)
	s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM monitors").Scan(&totalMonitors)
	s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM monitors WHERE enabled = 1").Scan(&activeMonitors)
	s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM waitlist").Scan(&waitlistCount)
	return map[string]int64{
		"total_users":     totalUsers,
		"total_monitors":  totalMonitors,
		"active_monitors": activeMonitors,
		"waitlist_count":  waitlistCount,
	}, nil
}

// ---------------------------------------------------------------------------
// Monitors
// ---------------------------------------------------------------------------

func (s *SQLiteStore) CreateMonitor(ctx context.Context, m *model.Monitor) (*model.Monitor, error) {
	now := time.Now().UTC().Format(timeFormat)

	encryptedAuth := ""
	if m.HttpAuth != "" && s.encryptionKey != "" {
		enc, err := crypto.Encrypt([]byte(m.HttpAuth), s.encryptionKey)
		if err != nil {
			return nil, fmt.Errorf("encrypt auth: %w", err)
		}
		encryptedAuth = enc
	}

	res, err := s.db.ExecContext(ctx,
		`INSERT INTO monitors (user_id, name, type, target, interval_secs, timeout_secs,
			keyword, keyword_type, keyword_match, expected_status, latency_warn_ms,
			confirmation_count, heartbeat_token, heartbeat_secret, ssl_warn_days,
			protocol, http_auth_type, http_auth,
			dns_record_type, dns_expected_value, dns_resolver,
			enabled, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'unknown', ?, ?)`,
		m.UserID, m.Name, m.Type, m.Target, m.IntervalSecs, m.TimeoutSecs,
		m.Keyword, m.KeywordType, m.KeywordMatch, m.ExpectedStatus, m.LatencyWarnMs,
		m.ConfirmationCount, m.HeartbeatToken, m.HeartbeatSecret, m.SSLWarnDays,
		m.Protocol, m.HttpAuthType, encryptedAuth,
		m.DnsRecordType, m.DnsExpectedValue, m.DnsResolver,
		boolToInt(m.Enabled),
		now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("insert monitor: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}

	if err := s.replaceAlertContacts(ctx, id, m.AlertContactIDs); err != nil {
		return nil, err
	}

	return s.GetMonitor(ctx, id, m.UserID)
}

func (s *SQLiteStore) GetMonitor(ctx context.Context, id, userID int64) (*model.Monitor, error) {
	m, err := s.scanMonitor(s.db.QueryRowContext(ctx,
		`SELECT `+monitorColumns+`
		FROM monitors WHERE id = ? AND user_id = ?`, id, userID,
	))
	if err != nil {
		return nil, err
	}

	ids, err := s.getAlertContactIDs(ctx, m.ID)
	if err != nil {
		return nil, err
	}
	m.AlertContactIDs = ids

	return m, nil
}

// CountMonitors returns the number of monitors owned by a user.
func (s *SQLiteStore) CountMonitors(ctx context.Context, userID int64) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM monitors WHERE user_id = ?", userID).Scan(&count)
	return count, err
}

// CountAlertContacts returns the number of alert contacts owned by a user.
func (s *SQLiteStore) CountAlertContacts(ctx context.Context, userID int64) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM alert_contacts WHERE user_id = ?", userID).Scan(&count)
	return count, err
}

// GetUserPlan returns the plan for a user.
func (s *SQLiteStore) GetUserPlan(ctx context.Context, userID int64) (string, error) {
	var plan string
	err := s.db.QueryRowContext(ctx, "SELECT plan FROM users WHERE id = ?", userID).Scan(&plan)
	if err != nil {
		return "free", err
	}
	return plan, nil
}

func (s *SQLiteStore) ListMonitors(ctx context.Context, userID int64) ([]model.Monitor, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+monitorColumns+`
		FROM monitors WHERE user_id = ? ORDER BY id`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list monitors: %w", err)
	}
	defer rows.Close()

	var monitors []model.Monitor
	for rows.Next() {
		m, err := s.scanMonitorRow(rows)
		if err != nil {
			return nil, err
		}
		ids, err := s.getAlertContactIDs(ctx, m.ID)
		if err != nil {
			return nil, err
		}
		m.AlertContactIDs = ids
		monitors = append(monitors, *m)
	}
	return monitors, rows.Err()
}

func (s *SQLiteStore) UpdateMonitor(ctx context.Context, m *model.Monitor) error {
	now := time.Now().UTC().Format(timeFormat)

	encryptedAuth := m.HttpAuth // may already be encrypted if unchanged
	if m.HttpAuth != "" && s.encryptionKey != "" && m.HttpAuthType != "none" {
		// Only re-encrypt if it looks like plaintext JSON (starts with '{').
		if len(m.HttpAuth) > 0 && m.HttpAuth[0] == '{' {
			enc, err := crypto.Encrypt([]byte(m.HttpAuth), s.encryptionKey)
			if err != nil {
				return fmt.Errorf("encrypt auth: %w", err)
			}
			encryptedAuth = enc
		}
	}
	if m.HttpAuthType == "none" {
		encryptedAuth = ""
	}

	_, err := s.db.ExecContext(ctx,
		`UPDATE monitors SET name=?, type=?, target=?, interval_secs=?, timeout_secs=?,
			keyword=?, keyword_type=?, keyword_match=?, expected_status=?, latency_warn_ms=?,
			confirmation_count=?, heartbeat_secret=?, ssl_warn_days=?,
			protocol=?, http_auth_type=?, http_auth=?,
			dns_record_type=?, dns_expected_value=?, dns_resolver=?,
			enabled=?, last_checked_at=?, updated_at=?
		WHERE id=? AND user_id=?`,
		m.Name, m.Type, m.Target, m.IntervalSecs, m.TimeoutSecs,
		m.Keyword, m.KeywordType, m.KeywordMatch, m.ExpectedStatus, m.LatencyWarnMs,
		m.ConfirmationCount, m.HeartbeatSecret, m.SSLWarnDays,
		m.Protocol, m.HttpAuthType, encryptedAuth,
		m.DnsRecordType, m.DnsExpectedValue, m.DnsResolver,
		boolToInt(m.Enabled),
		nil, now, m.ID, m.UserID,
	)
	if err != nil {
		return fmt.Errorf("update monitor: %w", err)
	}

	return s.replaceAlertContacts(ctx, m.ID, m.AlertContactIDs)
}

func (s *SQLiteStore) DeleteMonitor(ctx context.Context, id, userID int64) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM monitors WHERE id = ? AND user_id = ?", id, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ResetMonitorHistory wipes all check results and alert logs for a monitor
// and resets its state to unknown. Ownership is verified via user_id.
func (s *SQLiteStore) ResetMonitorHistory(ctx context.Context, id, userID int64) error {
	now := time.Now().UTC().Format(timeFormat)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx,
		`UPDATE monitors
		SET status = 'unknown', consecutive_fails = 0,
		    last_checked_at = NULL, ssl_expiry_at = NULL, updated_at = ?
		WHERE id = ? AND user_id = ?`,
		now, id, userID,
	)
	if err != nil {
		return fmt.Errorf("reset monitor state: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}

	if _, err := tx.ExecContext(ctx,
		"DELETE FROM check_results WHERE monitor_id = ?", id,
	); err != nil {
		return fmt.Errorf("delete check results: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		"DELETE FROM alert_log WHERE monitor_id = ?", id,
	); err != nil {
		return fmt.Errorf("delete alert log: %w", err)
	}

	return tx.Commit()
}

func (s *SQLiteStore) ResetLastChecked(ctx context.Context, id, userID int64) error {
	res, err := s.db.ExecContext(ctx,
		"UPDATE monitors SET last_checked_at = NULL WHERE id = ? AND user_id = ?", id, userID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLiteStore) SetMonitorEnabled(ctx context.Context, id, userID int64, enabled bool) error {
	now := time.Now().UTC().Format(timeFormat)
	res, err := s.db.ExecContext(ctx,
		"UPDATE monitors SET enabled = ?, updated_at = ? WHERE id = ? AND user_id = ?",
		boolToInt(enabled), now, id, userID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLiteStore) GetDueMonitors(ctx context.Context) ([]model.Monitor, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+monitorColumns+`
		FROM monitors
		WHERE enabled = 1
			AND (
				(type != 'heartbeat'
					AND (last_checked_at IS NULL
						OR last_checked_at <= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-' || interval_secs || ' seconds')))
				OR (type = 'heartbeat'
					AND heartbeat_last_ping IS NOT NULL
					AND heartbeat_last_ping <= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-' || interval_secs || ' seconds'))
			)`,
	)
	if err != nil {
		return nil, fmt.Errorf("get due monitors: %w", err)
	}
	defer rows.Close()

	var monitors []model.Monitor
	for rows.Next() {
		m, err := s.scanMonitorRow(rows)
		if err != nil {
			return nil, err
		}
		ids, err := s.getAlertContactIDs(ctx, m.ID)
		if err != nil {
			return nil, err
		}
		m.AlertContactIDs = ids
		monitors = append(monitors, *m)
	}
	return monitors, rows.Err()
}

func (s *SQLiteStore) UpdateMonitorStatus(ctx context.Context, id int64, status string, lastCheckedAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE monitors SET status = ?, last_checked_at = ?, updated_at = ? WHERE id = ?",
		status, lastCheckedAt.UTC().Format(timeFormat), time.Now().UTC().Format(timeFormat), id,
	)
	return err
}

func (s *SQLiteStore) replaceAlertContacts(ctx context.Context, monitorID int64, contactIDs []int64) error {
	if _, err := s.db.ExecContext(ctx,
		"DELETE FROM monitor_alert_contacts WHERE monitor_id = ?", monitorID,
	); err != nil {
		return fmt.Errorf("delete monitor alert contacts: %w", err)
	}

	for _, cid := range contactIDs {
		if _, err := s.db.ExecContext(ctx,
			"INSERT INTO monitor_alert_contacts (monitor_id, alert_contact_id) VALUES (?, ?)",
			monitorID, cid,
		); err != nil {
			return fmt.Errorf("insert monitor alert contact: %w", err)
		}
	}
	return nil
}

func (s *SQLiteStore) getAlertContactIDs(ctx context.Context, monitorID int64) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT alert_contact_id FROM monitor_alert_contacts WHERE monitor_id = ?", monitorID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

type scannable interface {
	Scan(dest ...any) error
}

func (s *SQLiteStore) scanMonitor(row *sql.Row) (*model.Monitor, error) {
	var m model.Monitor
	var enabled int
	var lastChecked, createdAt, updatedAt sql.NullString
	var heartbeatLastPing, sslExpiryAt sql.NullString

	err := row.Scan(
		&m.ID, &m.UserID, &m.Name, &m.Type, &m.Target,
		&m.IntervalSecs, &m.TimeoutSecs, &m.Keyword, &m.KeywordType, &m.KeywordMatch,
		&m.ExpectedStatus, &m.LatencyWarnMs,
		&m.ConfirmationCount, &m.ConsecutiveFails, &m.HeartbeatToken, &m.HeartbeatSecret, &heartbeatLastPing,
		&m.SSLWarnDays, &sslExpiryAt, &m.Protocol,
		&m.HttpAuthType, &m.HttpAuth,
		&m.DnsRecordType, &m.DnsExpectedValue, &m.DnsResolver,
		&enabled, &m.Status,
		&lastChecked, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	m.Enabled = enabled == 1
	m.HttpAuthConfigured = m.HttpAuthType != "" && m.HttpAuthType != "none"
	if lastChecked.Valid {
		t, _ := time.Parse(timeFormat, lastChecked.String)
		m.LastCheckedAt = &t
	}
	if heartbeatLastPing.Valid {
		t, _ := time.Parse(timeFormat, heartbeatLastPing.String)
		m.HeartbeatLastPing = &t
	}
	if sslExpiryAt.Valid {
		t, _ := time.Parse(timeFormat, sslExpiryAt.String)
		m.SSLExpiryAt = &t
	}
	if createdAt.Valid {
		m.CreatedAt, _ = time.Parse(timeFormat, createdAt.String)
	}
	if updatedAt.Valid {
		m.UpdatedAt, _ = time.Parse(timeFormat, updatedAt.String)
	}
	return &m, nil
}

func (s *SQLiteStore) scanMonitorRow(rows *sql.Rows) (*model.Monitor, error) {
	var m model.Monitor
	var enabled int
	var lastChecked, createdAt, updatedAt sql.NullString
	var heartbeatLastPing, sslExpiryAt sql.NullString

	err := rows.Scan(
		&m.ID, &m.UserID, &m.Name, &m.Type, &m.Target,
		&m.IntervalSecs, &m.TimeoutSecs, &m.Keyword, &m.KeywordType, &m.KeywordMatch,
		&m.ExpectedStatus, &m.LatencyWarnMs,
		&m.ConfirmationCount, &m.ConsecutiveFails, &m.HeartbeatToken, &m.HeartbeatSecret, &heartbeatLastPing,
		&m.SSLWarnDays, &sslExpiryAt, &m.Protocol,
		&m.HttpAuthType, &m.HttpAuth,
		&m.DnsRecordType, &m.DnsExpectedValue, &m.DnsResolver,
		&enabled, &m.Status,
		&lastChecked, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	m.Enabled = enabled == 1
	m.HttpAuthConfigured = m.HttpAuthType != "" && m.HttpAuthType != "none"
	if lastChecked.Valid {
		t, _ := time.Parse(timeFormat, lastChecked.String)
		m.LastCheckedAt = &t
	}
	if heartbeatLastPing.Valid {
		t, _ := time.Parse(timeFormat, heartbeatLastPing.String)
		m.HeartbeatLastPing = &t
	}
	if sslExpiryAt.Valid {
		t, _ := time.Parse(timeFormat, sslExpiryAt.String)
		m.SSLExpiryAt = &t
	}
	if createdAt.Valid {
		m.CreatedAt, _ = time.Parse(timeFormat, createdAt.String)
	}
	if updatedAt.Valid {
		m.UpdatedAt, _ = time.Parse(timeFormat, updatedAt.String)
	}
	return &m, nil
}

// DecryptMonitorAuth decrypts the HttpAuth field of a monitor.
// Returns the plaintext JSON or empty string if no auth is configured.
func (s *SQLiteStore) DecryptMonitorAuth(m *model.Monitor) (string, error) {
	if m.HttpAuth == "" || s.encryptionKey == "" {
		return "", nil
	}
	plaintext, err := crypto.Decrypt(m.HttpAuth, s.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("decrypt monitor auth: %w", err)
	}
	return string(plaintext), nil
}

// ---------------------------------------------------------------------------
// Heartbeat
// ---------------------------------------------------------------------------

func (s *SQLiteStore) UpdateHeartbeatPing(ctx context.Context, token string) (int64, error) {
	now := time.Now().UTC().Format(timeFormat)
	var id int64
	err := s.db.QueryRowContext(ctx,
		`UPDATE monitors SET heartbeat_last_ping = ?, updated_at = ?
		WHERE heartbeat_token = ? AND type = 'heartbeat'
		RETURNING id`,
		now, now, token,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("update heartbeat ping: %w", err)
	}
	return id, nil
}

func (s *SQLiteStore) GetMonitorByHeartbeatToken(ctx context.Context, token string) (*model.Monitor, error) {
	m, err := s.scanMonitor(s.db.QueryRowContext(ctx,
		`SELECT `+monitorColumns+`
		FROM monitors WHERE heartbeat_token = ? AND type = 'heartbeat'`, token,
	))
	if err != nil {
		return nil, err
	}

	ids, err := s.getAlertContactIDs(ctx, m.ID)
	if err != nil {
		return nil, err
	}
	m.AlertContactIDs = ids
	return m, nil
}

// ---------------------------------------------------------------------------
// Confirmation Count
// ---------------------------------------------------------------------------

func (s *SQLiteStore) IncrementConsecutiveFails(ctx context.Context, monitorID int64) (int, error) {
	var newVal int
	err := s.db.QueryRowContext(ctx,
		`UPDATE monitors SET consecutive_fails = consecutive_fails + 1
		WHERE id = ?
		RETURNING consecutive_fails`,
		monitorID,
	).Scan(&newVal)
	if err != nil {
		return 0, fmt.Errorf("increment consecutive fails: %w", err)
	}
	return newVal, nil
}

func (s *SQLiteStore) ResetConsecutiveFails(ctx context.Context, monitorID int64) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE monitors SET consecutive_fails = 0 WHERE id = ?", monitorID,
	)
	return err
}

// SaveCheckResult persists a check result and updates the monitor state in a
// single transaction. This replaces the previous 3 separate writes
// (InsertCheckResult + IncrementConsecutiveFails/ResetConsecutiveFails + UpdateMonitorStatus).
func (s *SQLiteStore) SaveCheckResult(ctx context.Context, monitorID int64, result *model.CheckResult, status string, resetFails bool, newFailCount int) error {
	now := time.Now().UTC().Format(timeFormat)
	checkedAt := result.CheckedAt.UTC().Format(timeFormat)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// 1. Insert check result.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO check_results (monitor_id, status, latency_ms, status_code, message, region, checked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		result.MonitorID, result.Status, result.LatencyMs, result.StatusCode, result.Message, result.Region, checkedAt,
	); err != nil {
		return fmt.Errorf("insert check result: %w", err)
	}

	// 2. Update monitor: status, last_checked_at, and consecutive_fails in one statement.
	var failsExpr string
	if resetFails {
		failsExpr = "0"
	} else {
		failsExpr = fmt.Sprintf("%d", newFailCount)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE monitors SET status = ?, last_checked_at = ?, consecutive_fails = `+failsExpr+`, updated_at = ? WHERE id = ?`,
		status, checkedAt, now, monitorID,
	); err != nil {
		return fmt.Errorf("update monitor: %w", err)
	}

	return tx.Commit()
}

// ---------------------------------------------------------------------------
// SSL
// ---------------------------------------------------------------------------

func (s *SQLiteStore) UpdateSSLExpiry(ctx context.Context, monitorID int64, expiryAt time.Time) error {
	now := time.Now().UTC().Format(timeFormat)
	_, err := s.db.ExecContext(ctx,
		"UPDATE monitors SET ssl_expiry_at = ?, updated_at = ? WHERE id = ?",
		expiryAt.UTC().Format(timeFormat), now, monitorID,
	)
	return err
}

// ---------------------------------------------------------------------------
// Status Pages
// ---------------------------------------------------------------------------

func (s *SQLiteStore) CreateStatusPage(ctx context.Context, sp *model.StatusPage) (*model.StatusPage, error) {
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	now := time.Now().UTC().Format(timeFormat)
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO status_pages (user_id, name, slug, token, description, password_hash, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sp.UserID, sp.Name, token, token, sp.Description, sp.PasswordHash, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("insert status page: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}

	if err := s.replaceStatusPageMonitors(ctx, id, sp.MonitorIDs); err != nil {
		return nil, err
	}

	return s.GetStatusPage(ctx, id, sp.UserID)
}

func (s *SQLiteStore) GetStatusPage(ctx context.Context, id, userID int64) (*model.StatusPage, error) {
	var sp model.StatusPage
	var passwordHash string
	var createdAt, updatedAt string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, name, token, description, password_hash, created_at, updated_at
		FROM status_pages WHERE id = ? AND user_id = ?`, id, userID,
	).Scan(&sp.ID, &sp.UserID, &sp.Name, &sp.Token, &sp.Description, &passwordHash, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	sp.PasswordHash = passwordHash
	sp.HasPassword = passwordHash != ""
	sp.CreatedAt, _ = time.Parse(timeFormat, createdAt)
	sp.UpdatedAt, _ = time.Parse(timeFormat, updatedAt)

	monitorIDs, err := s.getStatusPageMonitorIDs(ctx, sp.ID)
	if err != nil {
		return nil, err
	}
	sp.MonitorIDs = monitorIDs
	return &sp, nil
}

func (s *SQLiteStore) GetStatusPageByToken(ctx context.Context, token string) (*model.StatusPage, error) {
	var sp model.StatusPage
	var passwordHash string
	var createdAt, updatedAt string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, name, token, description, password_hash, created_at, updated_at
		FROM status_pages WHERE token = ?`, token,
	).Scan(&sp.ID, &sp.UserID, &sp.Name, &sp.Token, &sp.Description, &passwordHash, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	sp.PasswordHash = passwordHash
	sp.HasPassword = passwordHash != ""
	sp.CreatedAt, _ = time.Parse(timeFormat, createdAt)
	sp.UpdatedAt, _ = time.Parse(timeFormat, updatedAt)

	monitorIDs, err := s.getStatusPageMonitorIDs(ctx, sp.ID)
	if err != nil {
		return nil, err
	}
	sp.MonitorIDs = monitorIDs
	return &sp, nil
}

func (s *SQLiteStore) ListStatusPages(ctx context.Context, userID int64) ([]model.StatusPage, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, name, token, description, password_hash, created_at, updated_at
		FROM status_pages WHERE user_id = ? ORDER BY id`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list status pages: %w", err)
	}
	defer rows.Close()

	var pages []model.StatusPage
	for rows.Next() {
		var sp model.StatusPage
		var passwordHash string
		var createdAt, updatedAt string
		if err := rows.Scan(&sp.ID, &sp.UserID, &sp.Name, &sp.Token, &sp.Description, &passwordHash, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		sp.PasswordHash = passwordHash
		sp.HasPassword = passwordHash != ""
		sp.CreatedAt, _ = time.Parse(timeFormat, createdAt)
		sp.UpdatedAt, _ = time.Parse(timeFormat, updatedAt)

		monitorIDs, err := s.getStatusPageMonitorIDs(ctx, sp.ID)
		if err != nil {
			return nil, err
		}
		sp.MonitorIDs = monitorIDs
		pages = append(pages, sp)
	}
	return pages, rows.Err()
}

func (s *SQLiteStore) UpdateStatusPage(ctx context.Context, sp *model.StatusPage) error {
	now := time.Now().UTC().Format(timeFormat)
	_, err := s.db.ExecContext(ctx,
		`UPDATE status_pages SET name=?, description=?, password_hash=?, updated_at=?
		WHERE id=? AND user_id=?`,
		sp.Name, sp.Description, sp.PasswordHash, now, sp.ID, sp.UserID,
	)
	if err != nil {
		return fmt.Errorf("update status page: %w", err)
	}

	return s.replaceStatusPageMonitors(ctx, sp.ID, sp.MonitorIDs)
}

func (s *SQLiteStore) DeleteStatusPage(ctx context.Context, id, userID int64) error {
	res, err := s.db.ExecContext(ctx,
		"DELETE FROM status_pages WHERE id = ? AND user_id = ?", id, userID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLiteStore) GetStatusPageMonitors(ctx context.Context, statusPageID int64) ([]model.Monitor, error) {
	// Prefix each column with "m." for the JOIN query.
	prefixed := "m." + strings.ReplaceAll(strings.ReplaceAll(monitorColumns, "\n", ""), "\t", "")
	prefixed = strings.ReplaceAll(prefixed, ", ", ", m.")
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+prefixed+`
		FROM monitors m
		JOIN status_page_monitors spm ON m.id = spm.monitor_id
		WHERE spm.status_page_id = ?
		ORDER BY spm.sort_order`, statusPageID,
	)
	if err != nil {
		return nil, fmt.Errorf("get status page monitors: %w", err)
	}
	defer rows.Close()

	var monitors []model.Monitor
	for rows.Next() {
		m, err := s.scanMonitorRow(rows)
		if err != nil {
			return nil, err
		}
		monitors = append(monitors, *m)
	}
	return monitors, rows.Err()
}

// VerifyAlertContactOwnership checks that all given alert contact IDs belong to the specified user.
func (s *SQLiteStore) VerifyAlertContactOwnership(ctx context.Context, userID int64, contactIDs []int64) (bool, error) {
	if len(contactIDs) == 0 {
		return true, nil
	}

	placeholders := make([]string, len(contactIDs))
	args := make([]any, 0, len(contactIDs)+1)
	args = append(args, userID)
	for i, id := range contactIDs {
		placeholders[i] = "?"
		args = append(args, id)
	}

	query := fmt.Sprintf(
		"SELECT COUNT(*) FROM alert_contacts WHERE user_id = ? AND id IN (%s)",
		strings.Join(placeholders, ","),
	)

	var count int
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return false, err
	}
	return count == len(contactIDs), nil
}

// VerifyMonitorOwnership checks that all given monitor IDs belong to the specified user.
// Returns false if any monitor does not exist or belongs to another user.
func (s *SQLiteStore) VerifyMonitorOwnership(ctx context.Context, userID int64, monitorIDs []int64) (bool, error) {
	if len(monitorIDs) == 0 {
		return true, nil
	}

	placeholders := make([]string, len(monitorIDs))
	args := make([]any, 0, len(monitorIDs)+1)
	args = append(args, userID)
	for i, id := range monitorIDs {
		placeholders[i] = "?"
		args = append(args, id)
	}

	query := fmt.Sprintf(
		"SELECT COUNT(*) FROM monitors WHERE user_id = ? AND id IN (%s)",
		strings.Join(placeholders, ","),
	)

	var count int
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return false, err
	}
	return count == len(monitorIDs), nil
}

func (s *SQLiteStore) replaceStatusPageMonitors(ctx context.Context, statusPageID int64, monitorIDs []int64) error {
	if _, err := s.db.ExecContext(ctx,
		"DELETE FROM status_page_monitors WHERE status_page_id = ?", statusPageID,
	); err != nil {
		return fmt.Errorf("delete status page monitors: %w", err)
	}

	for i, mid := range monitorIDs {
		if _, err := s.db.ExecContext(ctx,
			"INSERT INTO status_page_monitors (status_page_id, monitor_id, sort_order) VALUES (?, ?, ?)",
			statusPageID, mid, i,
		); err != nil {
			return fmt.Errorf("insert status page monitor: %w", err)
		}
	}
	return nil
}

func (s *SQLiteStore) getStatusPageMonitorIDs(ctx context.Context, statusPageID int64) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT monitor_id FROM status_page_monitors WHERE status_page_id = ? ORDER BY sort_order",
		statusPageID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ---------------------------------------------------------------------------
// Check Results
// ---------------------------------------------------------------------------

func (s *SQLiteStore) InsertCheckResult(ctx context.Context, cr *model.CheckResult) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO check_results (monitor_id, status, latency_ms, status_code, message, region, checked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		cr.MonitorID, cr.Status, cr.LatencyMs, cr.StatusCode, cr.Message, cr.Region,
		cr.CheckedAt.UTC().Format(timeFormat),
	)
	return err
}

func (s *SQLiteStore) ListCheckResults(ctx context.Context, monitorID, userID int64, limit, offset int) ([]model.CheckResult, int, error) {
	// Verify ownership.
	var ownerID int64
	err := s.db.QueryRowContext(ctx, "SELECT user_id FROM monitors WHERE id = ?", monitorID).Scan(&ownerID)
	if err != nil {
		return nil, 0, fmt.Errorf("monitor not found: %w", err)
	}
	if ownerID != userID {
		return nil, 0, fmt.Errorf("monitor not found")
	}

	var total int
	err = s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM check_results WHERE monitor_id = ?", monitorID,
	).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, monitor_id, status, latency_ms, status_code, message, region, checked_at
		FROM check_results WHERE monitor_id = ?
		ORDER BY checked_at DESC LIMIT ? OFFSET ?`,
		monitorID, limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var results []model.CheckResult
	for rows.Next() {
		var cr model.CheckResult
		var checkedAt string
		if err := rows.Scan(&cr.ID, &cr.MonitorID, &cr.Status, &cr.LatencyMs,
			&cr.StatusCode, &cr.Message, &cr.Region, &checkedAt); err != nil {
			return nil, 0, err
		}
		cr.CheckedAt, _ = time.Parse(timeFormat, checkedAt)
		results = append(results, cr)
	}
	return results, total, rows.Err()
}

func (s *SQLiteStore) GetUptimePercentage(ctx context.Context, monitorID, userID int64, hours int) (float64, error) {
	// Verify ownership.
	var ownerID int64
	err := s.db.QueryRowContext(ctx, "SELECT user_id FROM monitors WHERE id = ?", monitorID).Scan(&ownerID)
	if err != nil {
		return 0, fmt.Errorf("monitor not found: %w", err)
	}
	if ownerID != userID {
		return 0, fmt.Errorf("monitor not found")
	}

	var total, up int
	err = s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(CASE WHEN status = 'up' THEN 1 ELSE 0 END), 0)
		FROM check_results
		WHERE monitor_id = ?
			AND checked_at >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ? || ' hours')`,
		monitorID, fmt.Sprintf("-%d", hours),
	).Scan(&total, &up)
	if err != nil {
		return 0, err
	}

	if total == 0 {
		return 100.0, nil
	}
	return float64(up) / float64(total) * 100.0, nil
}

// ---------------------------------------------------------------------------
// Alert Contacts
// ---------------------------------------------------------------------------

func (s *SQLiteStore) CreateAlertContact(ctx context.Context, ac *model.AlertContact, verifyToken string) (*model.AlertContact, error) {
	now := time.Now().UTC().Format(timeFormat)
	verified := 1
	if ac.Type == "email" && verifyToken != "" {
		verified = 0
	}
	res, err := s.db.ExecContext(ctx,
		"INSERT INTO alert_contacts (user_id, type, value, name, verified, verify_token, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		ac.UserID, ac.Type, ac.Value, ac.Name, verified, verifyToken, now,
	)
	if err != nil {
		return nil, fmt.Errorf("insert alert contact: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}

	ac.ID = id
	ac.Verified = verified == 1
	ac.CreatedAt, _ = time.Parse(timeFormat, now)
	return ac, nil
}

// VerifyAlertContact marks an alert contact as verified by token.
func (s *SQLiteStore) VerifyAlertContact(ctx context.Context, token string) error {
	res, err := s.db.ExecContext(ctx,
		"UPDATE alert_contacts SET verified = 1, verify_token = '' WHERE verify_token = ? AND verified = 0",
		token,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ResendVerification sets a new verify token for an unverified email contact.
func (s *SQLiteStore) ResendVerification(ctx context.Context, id, userID int64, token string) (string, error) {
	var email string
	err := s.db.QueryRowContext(ctx,
		"SELECT value FROM alert_contacts WHERE id = ? AND user_id = ? AND type = 'email' AND verified = 0",
		id, userID,
	).Scan(&email)
	if err != nil {
		return "", err
	}
	_, err = s.db.ExecContext(ctx,
		"UPDATE alert_contacts SET verify_token = ? WHERE id = ?",
		token, id,
	)
	return email, err
}

func (s *SQLiteStore) ListAlertContacts(ctx context.Context, userID int64) ([]model.AlertContact, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, user_id, type, value, name, verified, created_at FROM alert_contacts WHERE user_id = ? ORDER BY id",
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var contacts []model.AlertContact
	for rows.Next() {
		var ac model.AlertContact
		var verified int
		var createdAt string
		if err := rows.Scan(&ac.ID, &ac.UserID, &ac.Type, &ac.Value, &ac.Name, &verified, &createdAt); err != nil {
			return nil, err
		}
		ac.Verified = verified == 1
		ac.CreatedAt, _ = time.Parse(timeFormat, createdAt)
		contacts = append(contacts, ac)
	}
	return contacts, rows.Err()
}

func (s *SQLiteStore) GetAlertContact(ctx context.Context, id, userID int64) (*model.AlertContact, error) {
	var ac model.AlertContact
	var verified int
	var createdAt string
	err := s.db.QueryRowContext(ctx,
		"SELECT id, user_id, type, value, name, verified, created_at FROM alert_contacts WHERE id = ? AND user_id = ?",
		id, userID,
	).Scan(&ac.ID, &ac.UserID, &ac.Type, &ac.Value, &ac.Name, &verified, &createdAt)
	if err != nil {
		return nil, err
	}
	ac.Verified = verified == 1
	ac.CreatedAt, _ = time.Parse(timeFormat, createdAt)
	return &ac, nil
}

func (s *SQLiteStore) UpdateAlertContact(ctx context.Context, ac *model.AlertContact, verified int, verifyToken string) error {
	res, err := s.db.ExecContext(ctx,
		"UPDATE alert_contacts SET type = ?, value = ?, name = ?, verified = ?, verify_token = ? WHERE id = ? AND user_id = ?",
		ac.Type, ac.Value, ac.Name, verified, verifyToken, ac.ID, ac.UserID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLiteStore) DeleteAlertContact(ctx context.Context, id, userID int64) error {
	res, err := s.db.ExecContext(ctx,
		"DELETE FROM alert_contacts WHERE id = ? AND user_id = ?", id, userID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLiteStore) GetAlertContactsForMonitor(ctx context.Context, monitorID int64) ([]model.AlertContact, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT ac.id, ac.user_id, ac.type, ac.value, ac.name, ac.verified, ac.created_at
		FROM alert_contacts ac
		JOIN monitor_alert_contacts mac ON ac.id = mac.alert_contact_id
		WHERE mac.monitor_id = ?`, monitorID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var contacts []model.AlertContact
	for rows.Next() {
		var ac model.AlertContact
		var verified int
		var createdAt string
		if err := rows.Scan(&ac.ID, &ac.UserID, &ac.Type, &ac.Value, &ac.Name, &verified, &createdAt); err != nil {
			return nil, err
		}
		ac.Verified = verified == 1
		ac.CreatedAt, _ = time.Parse(timeFormat, createdAt)
		contacts = append(contacts, ac)
	}
	return contacts, rows.Err()
}

// ---------------------------------------------------------------------------
// Alert Log
// ---------------------------------------------------------------------------

// PruneCheckResults deletes check results older than the given number of days.
// Returns the number of deleted rows.
func (s *SQLiteStore) PruneCheckResults(ctx context.Context, retentionDays int) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM check_results
		WHERE checked_at < strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ? || ' days')`,
		fmt.Sprintf("-%d", retentionDays),
	)
	if err != nil {
		return 0, fmt.Errorf("prune check results: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// PruneAlertLogs deletes alert logs older than the given number of days.
// Returns the number of deleted rows.
func (s *SQLiteStore) PruneAlertLogs(ctx context.Context, retentionDays int) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM alert_log
		WHERE sent_at < strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ? || ' days')`,
		fmt.Sprintf("-%d", retentionDays),
	)
	if err != nil {
		return 0, fmt.Errorf("prune alert logs: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func (s *SQLiteStore) InsertAlertLog(ctx context.Context, al *model.AlertLog) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO alert_log (monitor_id, alert_contact_id, type, message, sent_at)
		VALUES (?, ?, ?, ?, ?)`,
		al.MonitorID, al.AlertContactID, al.Type, al.Message,
		al.SentAt.UTC().Format(timeFormat),
	)
	return err
}

// ---------------------------------------------------------------------------
// Waitlist
// ---------------------------------------------------------------------------

func (s *SQLiteStore) AddToWaitlist(ctx context.Context, email string) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT OR IGNORE INTO waitlist (email) VALUES (?)", email,
	)
	return err
}

// ---------------------------------------------------------------------------
// Daily Uptime
// ---------------------------------------------------------------------------

func (s *SQLiteStore) GetDailyUptime(ctx context.Context, monitorID int64, days int) ([]model.DailyUptime, error) {
	daysParam := fmt.Sprintf("-%d", days)
	rows, err := s.db.QueryContext(ctx,
		`SELECT
			substr(checked_at, 1, 10) as date,
			COUNT(*) as total,
			SUM(CASE WHEN status = 'up' THEN 1 ELSE 0 END) as up_count
		FROM check_results
		WHERE monitor_id = ?
			AND checked_at >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ? || ' days')
		GROUP BY substr(checked_at, 1, 10)
		ORDER BY date`,
		monitorID, daysParam,
	)
	if err != nil {
		return nil, fmt.Errorf("get daily uptime: %w", err)
	}
	defer rows.Close()

	dataByDate := make(map[string]model.DailyUptime)
	for rows.Next() {
		var date string
		var total, upCount int
		if err := rows.Scan(&date, &total, &upCount); err != nil {
			return nil, err
		}
		pct := 100.0
		if total > 0 {
			pct = float64(upCount) / float64(total) * 100.0
		}
		dataByDate[date] = model.DailyUptime{
			Date:        date,
			Percentage:  pct,
			TotalChecks: total,
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Fill in missing days
	now := time.Now().UTC()
	start := now.AddDate(0, 0, -days+1)
	var result []model.DailyUptime
	for d := start; !d.After(now); d = d.AddDate(0, 0, 1) {
		dateStr := d.Format("2006-01-02")
		if entry, ok := dataByDate[dateStr]; ok {
			result = append(result, entry)
		} else {
			result = append(result, model.DailyUptime{
				Date:        dateStr,
				Percentage:  100.0,
				TotalChecks: 0,
			})
		}
	}

	return result, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// API Keys
// ---------------------------------------------------------------------------

// CreateAPIKey stores a new API key (hashed). Returns the created APIKey.
func (s *SQLiteStore) CreateAPIKey(ctx context.Context, userID int64, name, prefix, keyHash string) (*model.APIKey, error) {
	now := time.Now().UTC().Format(timeFormat)
	res, err := s.db.ExecContext(ctx,
		"INSERT INTO api_keys (user_id, name, prefix, key_hash, created_at) VALUES (?, ?, ?, ?, ?)",
		userID, name, prefix, keyHash, now,
	)
	if err != nil {
		return nil, fmt.Errorf("insert api key: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("get last insert id: %w", err)
	}

	createdAt, _ := time.Parse(timeFormat, now)
	return &model.APIKey{
		ID:        id,
		UserID:    userID,
		Name:      name,
		Prefix:    prefix,
		CreatedAt: createdAt,
	}, nil
}

// ListAPIKeys returns all API keys for a user (no raw keys or hashes).
func (s *SQLiteStore) ListAPIKeys(ctx context.Context, userID int64) ([]model.APIKey, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, user_id, name, prefix, last_used_at, created_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC",
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()

	var keys []model.APIKey
	for rows.Next() {
		var k model.APIKey
		var lastUsed, created string
		var lastUsedPtr *string
		if err := rows.Scan(&k.ID, &k.UserID, &k.Name, &k.Prefix, &lastUsedPtr, &created); err != nil {
			return nil, fmt.Errorf("scan api key: %w", err)
		}
		k.CreatedAt, _ = time.Parse(timeFormat, created)
		if lastUsedPtr != nil {
			lastUsed = *lastUsedPtr
			t, _ := time.Parse(timeFormat, lastUsed)
			k.LastUsedAt = &t
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// DeleteAPIKey deletes an API key by ID for a user.
func (s *SQLiteStore) DeleteAPIKey(ctx context.Context, id, userID int64) error {
	res, err := s.db.ExecContext(ctx,
		"DELETE FROM api_keys WHERE id = ? AND user_id = ?",
		id, userID,
	)
	if err != nil {
		return fmt.Errorf("delete api key: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// GetUserIDByAPIKey looks up a user by API key. It extracts the prefix,
// queries candidate rows, compares SHA-256 hashes, updates last_used_at
// on match, and returns the user ID.
func (s *SQLiteStore) GetUserIDByAPIKey(ctx context.Context, key string) (int64, error) {
	if len(key) < 8 {
		return 0, fmt.Errorf("invalid api key")
	}

	prefix := key[:8]
	hash := sha256.Sum256([]byte(key))
	keyHash := hex.EncodeToString(hash[:])

	rows, err := s.db.QueryContext(ctx,
		"SELECT id, user_id, key_hash FROM api_keys WHERE prefix = ?",
		prefix,
	)
	if err != nil {
		return 0, fmt.Errorf("query api keys: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id, userID int64
		var storedHash string
		if err := rows.Scan(&id, &userID, &storedHash); err != nil {
			return 0, fmt.Errorf("scan api key: %w", err)
		}
		if storedHash == keyHash {
			now := time.Now().UTC().Format(timeFormat)
			_, _ = s.db.ExecContext(ctx,
				"UPDATE api_keys SET last_used_at = ? WHERE id = ?",
				now, id,
			)
			return userID, nil
		}
	}

	return 0, fmt.Errorf("invalid api key")
}
