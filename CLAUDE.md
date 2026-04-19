# pong-backend-go (Pong API)

Uptime/health monitoring REST API built in Go.

## Tech Stack

- Go 1.25, stdlib `net/http` router (Go 1.22+ pattern matching)
- SQLite via `modernc.org/sqlite` (pure Go, no CGO)
- Auth0 RS256 JWT validation + API key auth (`pong_` prefix, Bearer token)
- No ORM — raw SQL queries in `internal/store/`

## Monitor Types

- **HTTP/HTTPS** — GET/HEAD request, status code check, optional Basic Auth or custom header auth
- **Port (TCP/UDP)** — connects to host:port, checks if open (TCP dial or UDP probe)
- **Keyword** — HTTP request with keyword or regex match in response body
- **Heartbeat** — expects periodic pings; optional `X-Secret` header validation
- **SSL** — TLS certificate expiry check with configurable warning threshold
- **DNS** — resolves A/AAAA/MX/TXT/CNAME/NS records; optional expected-value substring match; optional custom resolver

## Project Structure

- `cmd/server/main.go` — entry point, wires all components
- `internal/api/` — HTTP handlers, middleware, router
- `internal/checker/` — health check engine, scheduler, worker pool
- `internal/alerter/` — alert dispatcher (webhook, email, slack)
- `internal/store/` — store interfaces (`iface.go`) and SQLite implementation (`sqlite.go`), migrations runner
- `internal/crypto/` — AES-256-GCM encryption for monitor credentials
- `internal/model/` — domain types
- `internal/config/` — env var parsing
- `internal/pruner/` — data pruning for check results and alert logs
- `migrations/` — SQL migration files

## API Routes

- `/api/v1/monitors/` — monitor CRUD, pause/resume, check now, reset history
- `/api/v1/alert-contacts/` — alert contact CRUD, email verification, test button
- `/api/v1/api-keys/` — API key management (`pong_` prefixed keys)
- `/api/v1/status-pages/` — status page CRUD (token-based public URLs, optional password)
- `/api/v1/uptime-timeline/` — daily uptime timeline data
- `/api/v1/waitlist/` — waitlist signup endpoint
- `/api/v1/admin/` — admin-only: stats, users, plan management, waitlist management
- `/heartbeat/{token}` — heartbeat ping endpoint

## Commands

- `go build ./...` — build
- `go test ./...` — test
- `go vet ./...` — lint
- `go run ./cmd/server` — run (requires AUTH0_DOMAIN, AUTH0_AUDIENCE env vars)
- `docker build -t ghm .` — build Docker image

## Key Design Decisions

- Auth is handled by Auth0; the API only validates tokens via JWKS
- API key auth supported alongside JWT (keys use `pong_` prefix, sent as Bearer tokens)
- Users are auto-provisioned on first authenticated request (from `sub` claim)
- Admin role: users with `admin` role get access to `/api/v1/admin/` endpoints
- Alerts fire on state transitions only (up->down, down->up), not on every check
- Confirmation count: N consecutive failures required before marking a monitor as down
- Alert contacts require email verification before alerts are sent
- Scheduler uses a tick-based design (1s tick, queries DB for due monitors)
- Worker pool is bounded (default 20 workers, buffered channel)
- Post-check writes are batched in a single transaction (insert result + update monitor status/fails)
- Store layer uses interfaces (CheckerStore, AlerterStore, PrunerStore, APIStore) for backend swappability
- Monitor credentials encrypted at rest with AES-256-GCM (ENCRYPTION_KEY env var)
- Status pages use token-based public URLs with optional password protection
- Pruner runs on a schedule, deleting check results and alert logs older than configurable retention period
- Data pruning: check results and alert logs are pruned based on `RETENTION_DAYS`
- Plan limits enforced when `ENFORCE_PLAN_LIMITS=true` (monitor count, min interval, contact count)
- Auth0 is optional: set `ADMIN_API_KEY` for API-key-only mode (self-hosted)

## Project Structure (additional)

- `bench/` — benchmark tool (`go run ./bench -monitors=500 -workers=20 -duration=30s`)
- `internal/config/plans.go` — plan tier definitions (free/pro/business/selfhosted)

## Environment Variables

- `AUTH0_DOMAIN` — Auth0 tenant (required unless ADMIN_API_KEY is set)
- `AUTH0_AUDIENCE` — Auth0 API identifier
- `ADMIN_API_KEY` — bootstrap admin API key (enables API-key-only mode)
- `BASE_URL` (default: `http://localhost:8080`) — public URL for email verification links
- `DATABASE_PATH` (default: `data/ghm.db`)
- `PORT` (default: `8080`)
- `WORKER_COUNT` (default: `20`)
- `CHECK_TICK_SECONDS` (default: `1`)
- `RETENTION_DAYS` (default: `90`) — how long to keep check results and alert logs
- `ENFORCE_PLAN_LIMITS` (default: `false`) — enable plan-based resource limits
- `REQUIRE_EMAIL_VERIFICATION` (default: `false`) — require email contacts to verify before receiving alerts
- `ENCRYPTION_KEY` — 64-char hex key for AES-256-GCM encryption of monitor credentials (required for HTTP auth)
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` — for email alerts
- `SMTP_FROM_NOREPLY` — noreply sender address for verification emails
