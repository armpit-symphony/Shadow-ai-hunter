# Shadow AI Hunter — Risk Assessment
*v2.0.0 | Prepared: 2026-04-09*

---

## CRITICAL — Do Not Ship to Production As-Is

### [C-1] NET_ADMIN / NET_RAW Capability in Docker
- **Location:** `docker-compose.yml` — `backend` service
- **Issue:** `NET_ADMIN | NET_RAW` Linux capabilities granted to the backend container
- **What this means:** The container can forge packets, sniff traffic, and perform man-in-the-middle attacks on the host network
- **Risk:** If the backend container is compromised, the attacker gains full network control of the host
- **Fix:** Remove `NET_ADMIN` capability entirely. For port scanning only, `NET_RAW` is sufficient. Create an isolated `scanner-worker` container with restricted capabilities if true packet injection is needed.

### [C-2] Hardcoded JWT Secret
- **Location:** `backend/auth.py` — `SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-jwt-secret-change-in-production")`
- **Issue:** Default fallback secret is a known string. If env var is not set (user forgets), all JWTs are forgeable.
- **Risk:** Account takeover for any user, including admins
- **Fix:** Fail fast on startup if `JWT_SECRET_KEY` is not set in non-dev environments. No fallback.

### [C-3] MongoDB Port Exposed Outside Container Network
- **Location:** `docker-compose.yml` — `mongodb` ports mapping `27017:27017`
- **Issue:** MongoDB port exposed directly to the host. If firewall is misconfigured, MongoDB accepts any connection (no auth by default in dev)
- **Risk:** Full data exfiltration or tampering if port is reachable
- **Fix:** Remove port mapping entirely. Backend communicates with MongoDB via internal container network. Add MongoDB auth and TLS.

---

## HIGH

### [H-1] No Rate Limiting on Any Endpoint
- **Location:** All routes in `backend/server.py`
- **Issue:** No rate limiting middleware. Brute-force attacks on `/api/auth/login` are trivial
- **Risk:** Credential stuffing, DoS, cost abuse
- **Fix:** Add `slowapi` or similar: 10 req/min on login, 100 req/min on read endpoints, 1000 req/min on scan creation

### [H-2] No Request Validation / Schema Enforcement
- **Location:** `POST /api/scans` body is parsed as dict and passed directly
- **Issue:** No Pydantic model enforcing required fields, types, and bounds
- **Risk:** Malformed data crashes workers or stored incorrectly
- **Fix:** Add `ScanCreate` Pydantic model with `target_type`, `target_value`, `modules_enabled`

### [H-3] Scanner Worker Has Full DB Write Access
- **Location:** All workers use same MongoDB user
- **Issue:** Workers directly write to `scans`, `devices`, `alerts`, `reports` collections
- **Risk:** A compromised worker can modify historical scan data or suppress alerts
- **Fix:** Workers use read-only connection. Only the orchestrator can write results.

### [H-4] Worker Secrets Visible in Environment
- **Location:** All worker env vars set in `docker-compose.yml`
- **Issue:** `JWT_SECRET_KEY`, MongoDB connection string visible to any container with env access
- **Risk:** Lateral movement if one container is compromised
- **Fix:** Use Docker secrets or a secrets manager for sensitive env vars

### [H-5] No Tenant Isolation in Queries
- **Location:** All MongoDB queries in workers don't filter by `tenant_id`
- **Issue:** One tenant's scans can accidentally return another tenant's data if IDs collide
- **Risk:** Cross-tenant data leakage in multi-tenant deployments
- **Fix:** All queries must include `tenant_id` filter (even if just "default" for now)

---

## MEDIUM

### [M-1] Redis Accessible Without Password
- **Location:** `docker-compose.yml` — `redis` service has no `command` auth config
- **Issue:** Redis accepts any connection on the internal network
- **Risk:** RQ job queue manipulation, pub/sub injection
- **Fix:** Set `REDIS_PASSWORD` env and configure Redis with `requirepass`

### [M-2] No Input Sanitization on `network_range`
- **Location:** `POST /api/scans` → `network_discovery_scan(network_range)`
- **Issue:** Arbitrary string passed to `ipaddress.ip_network()` — could trigger resource exhaustion on large CIDRs
- **Risk:** DoS via `/32` loops or massive scan (e.g., `0.0.0.0/0`)
- **Fix:** Validate CIDR size: reject anything larger than `/16` unless explicitly approved

### [M-3] Demo Endpoint Exposes Sensitive Data
- **Location:** `GET /api/demo/populate`, `GET /api/demo/users`
- **Issue:** Creates real users with real credentials, accessible without auth
- **Risk:** If demo mode is left enabled in non-dev, account takeover vector
- **Fix:** Demo endpoints must check `ENV == "development"` and return 404 in production

### [M-4] WebSocket Auth Token in Query Param
- **Location:** `ws://host/api/ws?token=<jwt>`
- **Issue:** JWT in URL query string gets logged in server logs, browser history, referrer headers
- **Risk:** Token theft via log exposure
- **Fix:** Pass JWT via `Authorization: Bearer <token>` header on WebSocket upgrade

### [M-5] No TLS Between Backend and MongoDB
- **Location:** `MONGO_URL` uses `mongodb://` not `mongodb+tls://`
- **Issue:** Credentials and data traverse the network in cleartext
- **Fix:** Enable TLS for MongoDB connections in production

### [M-6] PII Masking is Opt-In
- **Location:** `REPORT_MASK_PII=false` by default
- **Issue:** PDF/JSON reports contain unmasked IPs and usernames by default
- **Risk:** GDPR/HIPAA violations when reports are shared
- **Fix:** Default should be `true`; opt-out only for internal-only deployments

### [M-7] scanner_worker Fallback Has No Timeout on Per-IP Scan
- **Location:** `_socket_scan()` — TCP connect with `timeout=0.5` per port, but no global timeout per host
- **Issue:** A host that accepts connections slowly can block the worker for a long time
- **Risk:** Worker stall on specific targets
- **Fix:** Add per-host timeout (e.g., 30s max)

---

## LOW

### [L-1] No Health Check on Workers
- **Location:** `docker-compose.yml` — workers run as part of `backend` container with no individual health check
- **Issue:** A stuck worker won't be restarted by Docker
- **Fix:** Add script that pings Redis and exits 0/1 for Docker HEALTHCHECK

### [L-2] No Request IDs / Correlation IDs
- **Location:** No `X-Request-ID` header propagation
- **Issue:** Hard to trace a request through API → queue → worker → DB
- **Fix:** Add `X-Request-ID` generation at API layer, propagate through all workers

### [L-3] Default `bcrypt` Cost is Low for Production
- **Location:** `backend/auth.py` — default `CryptContext(schemes=["bcrypt"])`
- **Issue:** Default cost factor (~4 rounds) is too low for modern hardware
- **Fix:** Set `bcrypt__default_rounds = 12` explicitly

### [L-4] Refresh Token Rotation Not Implemented
- **Location:** `backend/auth.py` — stores refresh token hash but no rotation logic
- **Issue:** Refresh tokens are effectively long-lived bearer tokens
- **Fix:** Implement refresh token rotation (invalidate old on new login)

### [L-5] No Automatic DB Index Creation
- **Location:** No indexes defined on `scans._id`, `devices.ip_address`, `alerts.scan_id`, `events.scan_id`
- **Issue:** Performance degradation at scale
- **Fix:** Add indexes for common query patterns in `scripts/mongo-init.js`

---

## Summary Table

| ID | Severity | Category | Fix Complexity |
|----|----------|----------|----------------|
| C-1 | CRITICAL | Container security | Medium |
| C-2 | CRITICAL | Auth | Easy |
| C-3 | CRITICAL | Network exposure | Easy |
| H-1 | HIGH | Rate limiting | Easy |
| H-2 | HIGH | Input validation | Medium |
| H-3 | HIGH | Access control | Medium |
| H-4 | HIGH | Secrets management | Medium |
| H-5 | HIGH | Multi-tenancy | Medium |
| M-1 | MEDIUM | Auth | Easy |
| M-2 | MEDIUM | DoS protection | Easy |
| M-3 | MEDIUM | Exposure | Easy |
| M-4 | MEDIUM | Auth | Medium |
| M-5 | MEDIUM | TLS | Medium |
| M-6 | MEDIUM | Compliance | Easy |
| M-7 | MEDIUM | Reliability | Easy |
| L-1 | LOW | Operations | Easy |
| L-2 | LOW | Observability | Easy |
| L-3 | LOW | Cryptography | Easy |
| L-4 | LOW | Auth | Medium |
| L-5 | LOW | Performance | Easy |
