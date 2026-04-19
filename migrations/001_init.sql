-- Users
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    oauth_sub TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL DEFAULT '',
    is_admin INTEGER NOT NULL DEFAULT 0,
    plan TEXT NOT NULL DEFAULT 'free',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Monitors
CREATE TABLE IF NOT EXISTS monitors (
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
    protocol TEXT NOT NULL DEFAULT 'tcp',
    http_auth_type TEXT NOT NULL DEFAULT 'none',
    http_auth TEXT NOT NULL DEFAULT '',
    dns_record_type TEXT NOT NULL DEFAULT '',
    dns_expected_value TEXT NOT NULL DEFAULT '',
    dns_resolver TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'unknown',
    last_checked_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_monitors_user_id ON monitors(user_id);
CREATE INDEX IF NOT EXISTS idx_monitors_scheduler ON monitors(enabled, last_checked_at);

-- Check results (append-only, pruned by retention policy)
CREATE TABLE IF NOT EXISTS check_results (
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

CREATE INDEX IF NOT EXISTS idx_check_results_monitor_id ON check_results(monitor_id);
CREATE INDEX IF NOT EXISTS idx_check_results_checked_at ON check_results(monitor_id, checked_at);

-- Alert contacts
CREATE TABLE IF NOT EXISTS alert_contacts (
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

CREATE INDEX IF NOT EXISTS idx_alert_contacts_user_id ON alert_contacts(user_id);

-- Monitor <-> alert contact join table
CREATE TABLE IF NOT EXISTS monitor_alert_contacts (
    monitor_id INTEGER NOT NULL,
    alert_contact_id INTEGER NOT NULL,
    PRIMARY KEY (monitor_id, alert_contact_id),
    FOREIGN KEY (monitor_id) REFERENCES monitors(id) ON DELETE CASCADE,
    FOREIGN KEY (alert_contact_id) REFERENCES alert_contacts(id) ON DELETE CASCADE
);

-- Alert log (pruned by retention policy)
CREATE TABLE IF NOT EXISTS alert_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    monitor_id INTEGER NOT NULL,
    alert_contact_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    sent_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    FOREIGN KEY (monitor_id) REFERENCES monitors(id) ON DELETE CASCADE,
    FOREIGN KEY (alert_contact_id) REFERENCES alert_contacts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_alert_log_monitor_id ON alert_log(monitor_id);

-- Status pages
CREATE TABLE IF NOT EXISTS status_pages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    token TEXT NOT NULL DEFAULT '',
    description TEXT DEFAULT '',
    is_public INTEGER NOT NULL DEFAULT 1,
    password_hash TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Status page <-> monitor join table
CREATE TABLE IF NOT EXISTS status_page_monitors (
    status_page_id INTEGER NOT NULL,
    monitor_id INTEGER NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (status_page_id, monitor_id),
    FOREIGN KEY (status_page_id) REFERENCES status_pages(id) ON DELETE CASCADE,
    FOREIGN KEY (monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
);

-- API keys
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    last_used_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(prefix);

-- Waitlist
CREATE TABLE IF NOT EXISTS waitlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
