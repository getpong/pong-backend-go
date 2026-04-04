package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	Port             string
	DatabasePath     string
	Auth0Domain      string
	Auth0Audience    string
	AdminAPIKey      string
	BaseURL          string
	SMTPHost         string
	SMTPPort         string
	SMTPUser         string
	SMTPPass         string
	SMTPFrom         string
	SMTPFromNoreply  string
	WorkerCount       int
	CheckTickSeconds  int
	RetentionDays     int
	EnforcePlanLimits        bool
	RequireEmailVerification bool
}

func Load() (*Config, error) {
	cfg := &Config{
		Port:             envOrDefault("PORT", "8080"),
		DatabasePath:     envOrDefault("DATABASE_PATH", "data/ghm.db"),
		Auth0Domain:      os.Getenv("AUTH0_DOMAIN"),
		Auth0Audience:    os.Getenv("AUTH0_AUDIENCE"),
		AdminAPIKey:      os.Getenv("ADMIN_API_KEY"),
		BaseURL:          envOrDefault("BASE_URL", "http://localhost:8080"),
		SMTPHost:         os.Getenv("SMTP_HOST"),
		SMTPPort:         os.Getenv("SMTP_PORT"),
		SMTPUser:         os.Getenv("SMTP_USER"),
		SMTPPass:         os.Getenv("SMTP_PASS"),
		SMTPFrom:         os.Getenv("SMTP_FROM"),
		SMTPFromNoreply:  os.Getenv("SMTP_FROM_NOREPLY"),
		WorkerCount:       20,
		CheckTickSeconds:  1,
		RetentionDays:     90,
		EnforcePlanLimits:        os.Getenv("ENFORCE_PLAN_LIMITS") == "true",
		RequireEmailVerification: os.Getenv("REQUIRE_EMAIL_VERIFICATION") == "true",
	}

	// Auth0 is optional if ADMIN_API_KEY is set (API-key-only mode).
	if cfg.Auth0Domain == "" && cfg.AdminAPIKey == "" {
		return nil, fmt.Errorf("either AUTH0_DOMAIN or ADMIN_API_KEY must be set")
	}

	if v := os.Getenv("WORKER_COUNT"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid WORKER_COUNT %q: %w", v, err)
		}
		cfg.WorkerCount = n
	}

	if v := os.Getenv("CHECK_TICK_SECONDS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid CHECK_TICK_SECONDS %q: %w", v, err)
		}
		cfg.CheckTickSeconds = n
	}

	if v := os.Getenv("RETENTION_DAYS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid RETENTION_DAYS %q: %w", v, err)
		}
		cfg.RetentionDays = n
	}

	return cfg, nil
}

// Auth0Enabled returns true if Auth0 is configured.
func (c *Config) Auth0Enabled() bool {
	return c.Auth0Domain != "" && c.Auth0Audience != ""
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
