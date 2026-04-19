-- Rebuild tables without restrictive CHECK constraints so new enum values
-- (monitor types, alert contact types, statuses, etc.) can be added without
-- a schema migration. Validation is enforced at the API layer.
--
-- The migrator runs this with foreign_keys = OFF so DROP TABLE does not
-- cascade into child tables. Row IDs are preserved on each copy.

-- monitors
CREATE TABLE monitors_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    interval_secs INTEGER NOT NULL DEFAULT 300,
    timeout_secs INTEGER NOT NULL DEFAULT 30,
    keyword TEXT DEFAULT '',
    keyword_type TEXT DEFAULT '',
    keyword_match TEXT NOT NULL DEFAULT 'exact',
    expected_status INTEGER DEFAULT 0,
    latency_warn_ms INTEGER DEFAULT 0,
    confirmation_count INTEGER NOT NULL DEFAULT 1,
    consecutive_fails INTEGER NOT NULL DEFAULT 0,
    heartbeat_token TEXT DEFAULT '',
    heartbeat_secret TEXT DEFAULT '',
    heartbeat_last_ping TEXT,
    ssl_warn_days INTEGER NOT NULL DEFAULT 30,
    ssl_expiry_at TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'unknown',
    last_checked_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    http_auth_type TEXT NOT NULL DEFAULT 'none',
    http_auth TEXT NOT NULL DEFAULT '',
    protocol TEXT NOT NULL DEFAULT 'tcp',
    dns_record_type TEXT NOT NULL DEFAULT '',
    dns_expected_value TEXT NOT NULL DEFAULT '',
    dns_resolver TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

INSERT INTO monitors_new SELECT
    id, user_id, name, type, target, interval_secs, timeout_secs,
    keyword, keyword_type, keyword_match, expected_status, latency_warn_ms,
    confirmation_count, consecutive_fails, heartbeat_token, heartbeat_secret, heartbeat_last_ping,
    ssl_warn_days, ssl_expiry_at, enabled, status, last_checked_at,
    created_at, updated_at,
    http_auth_type, http_auth, protocol,
    dns_record_type, dns_expected_value, dns_resolver
FROM monitors;

DROP TABLE monitors;
ALTER TABLE monitors_new RENAME TO monitors;
CREATE INDEX IF NOT EXISTS idx_monitors_user_id ON monitors(user_id);
CREATE INDEX IF NOT EXISTS idx_monitors_scheduler ON monitors(enabled, last_checked_at);

-- check_results
CREATE TABLE check_results_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    monitor_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    latency_ms INTEGER NOT NULL DEFAULT 0,
    status_code INTEGER DEFAULT 0,
    message TEXT DEFAULT '',
    region TEXT NOT NULL DEFAULT 'default',
    checked_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    FOREIGN KEY (monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
);
INSERT INTO check_results_new SELECT id, monitor_id, status, latency_ms, status_code, message, region, checked_at FROM check_results;
DROP TABLE check_results;
ALTER TABLE check_results_new RENAME TO check_results;
CREATE INDEX IF NOT EXISTS idx_check_results_monitor_id ON check_results(monitor_id);
CREATE INDEX IF NOT EXISTS idx_check_results_checked_at ON check_results(monitor_id, checked_at);

-- alert_contacts
CREATE TABLE alert_contacts_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    name TEXT NOT NULL,
    verified INTEGER NOT NULL DEFAULT 1,
    verify_token TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
INSERT INTO alert_contacts_new SELECT id, user_id, type, value, name, verified, verify_token, created_at FROM alert_contacts;
DROP TABLE alert_contacts;
ALTER TABLE alert_contacts_new RENAME TO alert_contacts;
CREATE INDEX IF NOT EXISTS idx_alert_contacts_user_id ON alert_contacts(user_id);

-- alert_log
CREATE TABLE alert_log_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    monitor_id INTEGER NOT NULL,
    alert_contact_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    sent_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    FOREIGN KEY (monitor_id) REFERENCES monitors(id) ON DELETE CASCADE,
    FOREIGN KEY (alert_contact_id) REFERENCES alert_contacts(id) ON DELETE CASCADE
);
INSERT INTO alert_log_new SELECT id, monitor_id, alert_contact_id, type, message, sent_at FROM alert_log;
DROP TABLE alert_log;
ALTER TABLE alert_log_new RENAME TO alert_log;
CREATE INDEX IF NOT EXISTS idx_alert_log_monitor_id ON alert_log(monitor_id);
