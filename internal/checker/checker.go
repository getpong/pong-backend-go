package checker

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/getpong/pong-backend-go/internal/model"
)

// Checker defines the interface for performing health checks on monitors.
type Checker interface {
	Check(ctx context.Context, m model.Monitor) model.CheckResult
}

// AuthDecryptor decrypts the HttpAuth blob for a monitor.
type AuthDecryptor func(m *model.Monitor) (string, error)

// HTTPChecker performs HTTP-based health checks.
type HTTPChecker struct {
	client      *http.Client
	decryptAuth AuthDecryptor
}

// NewHTTPChecker returns an HTTPChecker with sensible defaults.
// The per-request timeout is set from the monitor config at check time.
func NewHTTPChecker(decryptAuth AuthDecryptor) *HTTPChecker {
	return &HTTPChecker{
		client: &http.Client{
			// Disable automatic redirects so we capture the actual status code.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		decryptAuth: decryptAuth,
	}
}

// Check performs an HTTP check against the monitor's target and returns the result.
func (h *HTTPChecker) Check(ctx context.Context, m model.Monitor) model.CheckResult {
	now := time.Now()
	result := model.CheckResult{
		MonitorID: m.ID,
		CheckedAt: now,
	}

	timeout := time.Duration(m.TimeoutSecs) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.Target, nil)
	if err != nil {
		result.Status = "down"
		result.Message = fmt.Sprintf("failed to create request: %v", err)
		return result
	}
	req.Header.Set("User-Agent", "pong-backend-go/1.0")

	// Apply HTTP authentication if configured.
	if (m.HttpAuthType == "basic" || m.HttpAuthType == "header") && h.decryptAuth != nil {
		authJSON, err := h.decryptAuth(&m)
		if err != nil {
			result.Status = "down"
			result.Message = fmt.Sprintf("failed to decrypt auth: %v", err)
			return result
		}
		if authJSON != "" {
			var raw map[string]string
			if err := json.Unmarshal([]byte(authJSON), &raw); err == nil {
				switch raw["type"] {
				case "basic":
					req.SetBasicAuth(raw["username"], raw["password"])
				case "header":
					req.Header.Set(raw["header"], raw["value"])
				}
			}
		}
	}

	start := time.Now()
	resp, err := h.client.Do(req)
	latency := time.Since(start)
	result.LatencyMs = int(latency.Milliseconds())

	if err != nil {
		result.Status = "down"
		result.Message = fmt.Sprintf("request failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	expectedStatus := m.ExpectedStatus
	if expectedStatus == 0 {
		expectedStatus = http.StatusOK
	}

	if resp.StatusCode != expectedStatus {
		result.Status = "down"
		result.Message = fmt.Sprintf("unexpected status code: got %d, want %d", resp.StatusCode, expectedStatus)
		return result
	}

	// Keyword checking for keyword-type monitors.
	if m.Keyword != "" && m.KeywordType != "" {
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB limit
		if err != nil {
			result.Status = "down"
			result.Message = fmt.Sprintf("failed to read response body: %v", err)
			return result
		}

		bodyStr := string(body)
		var matches bool

		if m.KeywordMatch == "regex" {
			re, err := regexp.Compile(m.Keyword)
			if err != nil {
				result.Status = "down"
				result.Message = fmt.Sprintf("invalid regex pattern: %v", err)
				return result
			}
			matches = re.MatchString(bodyStr)
		} else {
			matches = strings.Contains(bodyStr, m.Keyword)
		}

		switch m.KeywordType {
		case "contains":
			if !matches {
				result.Status = "down"
				result.Message = fmt.Sprintf("keyword %q not found in response body", m.Keyword)
				return result
			}
		case "not_contains":
			if matches {
				result.Status = "down"
				result.Message = fmt.Sprintf("keyword %q found in response body (expected absent)", m.Keyword)
				return result
			}
		}
	}

	result.Status = "up"
	result.Message = "OK"
	return result
}

// SSLChecker checks the TLS certificate expiry of a target host.
type SSLChecker struct{}

// Check performs a TLS handshake against the monitor's target and checks the
// certificate expiry date. If the certificate expires within SSLWarnDays days
// the result status is "down", otherwise "up".
func (c *SSLChecker) Check(ctx context.Context, m model.Monitor) model.CheckResult {
	now := time.Now()
	result := model.CheckResult{
		MonitorID: m.ID,
		CheckedAt: now,
	}

	host := m.Target
	// Strip protocol prefix if present.
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	// Strip path.
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}

	// Add default port if not specified.
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "443")
	}

	timeout := time.Duration(m.TimeoutSecs) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	dialer := &net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := tls.DialWithDialer(dialer, "tcp", host, &tls.Config{
		InsecureSkipVerify: false,
	})
	latency := time.Since(start)
	result.LatencyMs = int(latency.Milliseconds())

	if err != nil {
		result.Status = "down"
		result.Message = fmt.Sprintf("TLS connection failed: %v", err)
		return result
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		result.Status = "down"
		result.Message = "no peer certificates received"
		return result
	}

	leaf := certs[0]
	expiresAt := leaf.NotAfter
	daysUntilExpiry := int(time.Until(expiresAt).Hours() / 24)

	warnDays := m.SSLWarnDays
	if warnDays == 0 {
		warnDays = 30
	}

	// Use a parseable message format: "SSL_EXPIRY:<RFC3339> ..." so the
	// scheduler can extract the expiry date without extra struct fields.
	expiryStr := expiresAt.UTC().Format(time.RFC3339)

	if daysUntilExpiry <= warnDays {
		result.Status = "down"
		result.Message = fmt.Sprintf("SSL_EXPIRY:%s SSL certificate expires on %s (%d days)",
			expiryStr, expiresAt.Format("2006-01-02"), daysUntilExpiry)
	} else {
		result.Status = "up"
		result.Message = fmt.Sprintf("SSL_EXPIRY:%s SSL certificate expires in %d days",
			expiryStr, daysUntilExpiry)
	}

	return result
}

// HeartbeatChecker is a passive checker for heartbeat monitors. It determines
// status based on whether a ping has been received within the expected interval.
type HeartbeatChecker struct{}

// Check evaluates whether the monitor has received a heartbeat ping within the
// configured interval. If HeartbeatLastPing is nil or older than IntervalSecs,
// the result status is "down"; otherwise "up".
func (c *HeartbeatChecker) Check(ctx context.Context, m model.Monitor) model.CheckResult {
	now := time.Now()
	result := model.CheckResult{
		MonitorID: m.ID,
		CheckedAt: now,
	}

	if m.HeartbeatLastPing == nil {
		result.Status = "down"
		result.Message = "No ping received"
		return result
	}

	elapsed := now.Sub(*m.HeartbeatLastPing)
	interval := time.Duration(m.IntervalSecs) * time.Second
	if interval == 0 {
		interval = 60 * time.Second
	}

	if elapsed > interval {
		result.Status = "down"
		result.Message = fmt.Sprintf("Last ping: %s (overdue by %s)",
			m.HeartbeatLastPing.Format(time.RFC3339), (elapsed - interval).Truncate(time.Second))
	} else {
		result.Status = "up"
		result.Message = fmt.Sprintf("Last ping: %s", m.HeartbeatLastPing.Format(time.RFC3339))
	}

	return result
}

// PortChecker checks if a TCP or UDP port is open.
type PortChecker struct{}

// Check performs a TCP or UDP probe to the monitor's target (host:port) and
// reports whether the connection succeeds within the configured timeout.
// For UDP, a small probe packet is sent; if no ICMP rejection is received
// within the timeout the port is considered open.
func (c *PortChecker) Check(ctx context.Context, m model.Monitor) model.CheckResult {
	now := time.Now()
	result := model.CheckResult{
		MonitorID: m.ID,
		CheckedAt: now,
	}

	target := m.Target
	if _, _, err := net.SplitHostPort(target); err != nil {
		result.Status = "down"
		result.Message = fmt.Sprintf("invalid target %q: must be host:port", target)
		return result
	}

	timeout := time.Duration(m.TimeoutSecs) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	protocol := m.Protocol
	if protocol == "" {
		protocol = "tcp"
	}

	dialer := &net.Dialer{Timeout: timeout}
	start := time.Now()

	if protocol == "udp" {
		conn, err := dialer.DialContext(ctx, "udp", target)
		latency := time.Since(start)
		result.LatencyMs = int(latency.Milliseconds())

		if err != nil {
			result.Status = "down"
			result.Message = fmt.Sprintf("connection failed: %v", err)
			return result
		}
		defer conn.Close()

		// Send a small probe and wait for a response or timeout.
		conn.SetDeadline(time.Now().Add(timeout))
		if _, err := conn.Write([]byte{0}); err != nil {
			result.Status = "down"
			result.Message = fmt.Sprintf("write failed: %v", err)
			return result
		}

		buf := make([]byte, 1)
		_, err = conn.Read(buf)
		if err != nil {
			// Timeout means no ICMP rejection — port is likely open (or filtered).
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				result.Status = "up"
				result.Message = fmt.Sprintf("udp port open (no rejection), latency %dms", result.LatencyMs)
				return result
			}
			// Any other error (e.g. ICMP port unreachable) means closed.
			result.Status = "down"
			result.Message = fmt.Sprintf("port closed: %v", err)
			return result
		}

		result.Status = "up"
		result.Message = fmt.Sprintf("udp port open (responded), latency %dms", result.LatencyMs)
		return result
	}

	// TCP
	conn, err := dialer.DialContext(ctx, "tcp", target)
	latency := time.Since(start)
	result.LatencyMs = int(latency.Milliseconds())

	if err != nil {
		result.Status = "down"
		result.Message = fmt.Sprintf("connection failed: %v", err)
		return result
	}
	conn.Close()

	result.Status = "up"
	result.Message = fmt.Sprintf("port open, latency %dms", result.LatencyMs)
	return result
}
