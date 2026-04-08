package api

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"

	"github.com/getpong/pong-backend-go/internal/store"
	"time"
)

type contextKey string

const userIDKey contextKey = "userID"

// UserIDFromContext extracts the authenticated user ID from the request context.
func UserIDFromContext(ctx context.Context) int64 {
	id, _ := ctx.Value(userIDKey).(int64)
	return id
}

// UserProvisioner creates or retrieves a local user from an Auth0 subject.
type UserProvisioner interface {
	EnsureUser(ctx context.Context, auth0Sub string, email string) (int64, error)
}

// APIKeyValidator validates an API key and returns the associated user ID.
type APIKeyValidator interface {
	GetUserIDByAPIKey(ctx context.Context, key string) (int64, error)
}

// jwksCache caches RSA public keys fetched from Auth0's JWKS endpoint.
type jwksCache struct {
	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	ttl       time.Duration
	jwksURL   string
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func newJWKSCache(domain string) *jwksCache {
	return &jwksCache{
		keys:    make(map[string]*rsa.PublicKey),
		ttl:     1 * time.Hour,
		jwksURL: fmt.Sprintf("https://%s/.well-known/jwks.json", domain),
	}
}

func (c *jwksCache) getKey(kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	if time.Since(c.fetchedAt) < c.ttl {
		if key, ok := c.keys[kid]; ok {
			c.mu.RUnlock()
			return key, nil
		}
	}
	c.mu.RUnlock()

	if err := c.refresh(); err != nil {
		return nil, err
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	key, ok := c.keys[kid]
	if !ok {
		return nil, fmt.Errorf("key %q not found in JWKS", kid)
	}
	return key, nil
}

func (c *jwksCache) refresh() error {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(c.jwksURL)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS returned status %d", resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("decode JWKS: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey)
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" || k.Use != "sig" {
			continue
		}
		pub, err := parseRSAPublicKey(k.N, k.E)
		if err != nil {
			slog.Warn("skipping invalid JWKS key", "kid", k.Kid, "error", err)
			continue
		}
		keys[k.Kid] = pub
	}

	c.mu.Lock()
	c.keys = keys
	c.fetchedAt = time.Now()
	c.mu.Unlock()

	return nil
}

func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type jwtClaims struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Aud   any    `json:"aud"`
	Iss   string `json:"iss"`
	Exp   int64  `json:"exp"`
}

func (c *jwtClaims) hasAudience(aud string) bool {
	switch v := c.Aud.(type) {
	case string:
		return v == aud
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == aud {
				return true
			}
		}
	}
	return false
}

// APIKeyOnlyMiddleware validates only API keys (pong_ prefix). Used when Auth0 is not configured.
func APIKeyOnlyMiddleware(akValidator APIKeyValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if header == "" {
				respondError(w, http.StatusUnauthorized, "missing authorization header")
				return
			}

			parts := strings.SplitN(header, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				respondError(w, http.StatusUnauthorized, "invalid authorization header")
				return
			}

			userID, err := akValidator.GetUserIDByAPIKey(r.Context(), parts[1])
			if err != nil {
				respondError(w, http.StatusUnauthorized, "invalid api key")
				return
			}
			ctx := context.WithValue(r.Context(), userIDKey, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Auth0Middleware validates Auth0-issued RS256 JWT tokens or API keys,
// auto-provisions local users, and injects the user ID into the request context.
func Auth0Middleware(domain, audience string, provisioner UserProvisioner, apiKeyValidator ...APIKeyValidator) func(http.Handler) http.Handler {
	cache := newJWKSCache(domain)
	issuer := fmt.Sprintf("https://%s/", domain)

	var akValidator APIKeyValidator
	if len(apiKeyValidator) > 0 {
		akValidator = apiKeyValidator[0]
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if header == "" {
				respondError(w, http.StatusUnauthorized, "missing authorization header")
				return
			}

			parts := strings.SplitN(header, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				respondError(w, http.StatusUnauthorized, "invalid authorization header")
				return
			}

			token := parts[1]

			// API key flow: keys start with "pong_".
			if strings.HasPrefix(token, "pong_") && akValidator != nil {
				userID, err := akValidator.GetUserIDByAPIKey(r.Context(), token)
				if err != nil {
					respondError(w, http.StatusUnauthorized, "invalid api key")
					return
				}
				ctx := context.WithValue(r.Context(), userIDKey, userID)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			segments := strings.Split(token, ".")
			if len(segments) != 3 {
				respondError(w, http.StatusUnauthorized, "malformed token")
				return
			}

			// Decode and validate header.
			headerJSON, err := base64.RawURLEncoding.DecodeString(segments[0])
			if err != nil {
				respondError(w, http.StatusUnauthorized, "invalid token header")
				return
			}
			var hdr jwtHeader
			if err := json.Unmarshal(headerJSON, &hdr); err != nil {
				respondError(w, http.StatusUnauthorized, "invalid token header")
				return
			}
			if hdr.Alg != "RS256" {
				respondError(w, http.StatusUnauthorized, "unsupported signing algorithm")
				return
			}

			// Decode and validate claims.
			claimsJSON, err := base64.RawURLEncoding.DecodeString(segments[1])
			if err != nil {
				respondError(w, http.StatusUnauthorized, "invalid token claims")
				return
			}
			var claims jwtClaims
			if err := json.Unmarshal(claimsJSON, &claims); err != nil {
				respondError(w, http.StatusUnauthorized, "invalid token claims")
				return
			}

			if claims.Iss != issuer {
				respondError(w, http.StatusUnauthorized, "invalid token issuer")
				return
			}
			if !claims.hasAudience(audience) {
				respondError(w, http.StatusUnauthorized, "invalid token audience")
				return
			}
			if time.Now().Unix() > claims.Exp {
				respondError(w, http.StatusUnauthorized, "token expired")
				return
			}
			if claims.Sub == "" {
				respondError(w, http.StatusUnauthorized, "missing sub claim")
				return
			}

			// Verify RS256 signature.
			pubKey, err := cache.getKey(hdr.Kid)
			if err != nil {
				respondError(w, http.StatusUnauthorized, "unable to verify token signature")
				return
			}

			signingInput := segments[0] + "." + segments[1]
			hash := sha256.Sum256([]byte(signingInput))
			sig, err := base64.RawURLEncoding.DecodeString(segments[2])
			if err != nil {
				respondError(w, http.StatusUnauthorized, "invalid token signature")
				return
			}
			if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], sig); err != nil {
				respondError(w, http.StatusUnauthorized, "invalid token signature")
				return
			}

			// Auto-provision local user.
			userID, err := provisioner.EnsureUser(r.Context(), claims.Sub, claims.Email)
			if err != nil {
				slog.Error("failed to provision user", "sub", claims.Sub, "error", err)
				respondError(w, http.StatusInternalServerError, "failed to provision user")
				return
			}

			ctx := context.WithValue(r.Context(), userIDKey, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// AdminMiddleware checks that the authenticated user has admin privileges.
func AdminMiddleware(s store.APIStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := UserIDFromContext(r.Context())
			if userID == 0 {
				respondError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			isAdmin, err := s.IsAdmin(r.Context(), userID)
			if err != nil || !isAdmin {
				respondError(w, http.StatusNotFound, "not found")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CORSMiddleware adds permissive CORS headers for development.
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.statusCode = code
	sr.ResponseWriter.WriteHeader(code)
}

// LoggingMiddleware logs method, path, status code, and duration.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rec, r)
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.statusCode,
			"duration", time.Since(start),
		)
	})
}
