# Changelog

## v2.1.0 — 2026-04-10 (Phase 2)

### Added
- **MongoDB-backed API key store** (`api_keys` collection) — keys created/revoked via API without restarting the service; 60s in-process cache for validation
- **`POST /admin/api-keys`** — create a new project-bound API key; returns plaintext once
- **`GET /admin/api-keys`** — list all keys (masked prefix only, never exposes full key)
- **`DELETE /admin/api-keys/{api_key}`** — soft-revoke a key (`active=false`); immediately invalidates cache
- **`GET /api/usage`** — read usage records per project with optional `from_date`/`to_date` filter
- **`GET /api/alerts/{alert_id}`** — single alert detail with notification status fields
- **`PATCH /api/alerts/{alert_id}`** — mark alert acknowledged/resolved (operator-only)
- **`POST /api/alerts/{alert_id}/retry-notification`** — re-fire outbound webhook for a failed alert
- **Outbound webhook notifications** — `ALERT_WEBHOOK_URL` env var; fires on high/critical alerts; 10s timeout; failures never block detection pipeline
- **Notification delivery status** — `notification_attempted`, `notification_sent`, `notification_error`, `notification_last_attempt_at` written to every alert after notification attempt
- **`notification_status` filter** on `GET /api/alerts` — filter by `sent`, `failed`, `attempted`, `unattempted`
- **Usage metering** — `usage_records` collection; atomic `$inc` upsert per project per UTC day on every ingest

### Changed
- `INGEST_API_KEYS` env var now acts as static fallback; MongoDB keys take priority
- Auth DB initialization (`init_db`) now called at startup — JWT-protected endpoints work correctly
- Backend gracefully handles missing MongoDB indexes (non-fatal warnings)

## v2.0.1 — 2026-02-27
### Added
- Cookie-based auth with refresh tokens and CSRF protection.
- Admin audit log and SIEM delivery tracking.
- Redis pub/sub for WebSocket events with Mongo fallback.
- Segment inference via `SEGMENT_MAP` and retention TTLs.

### Changed
- Python 3.12 dependency pins (`numpy`, `torch`, `bcrypt`, `httpx`).
- Time handling switched to timezone-aware UTC.
- Scan state transitions guarded for worker updates.

### Fixed
- Test client compatibility with httpx.
- Bcrypt backend stability for passlib.
