# Backend Runbook — Shadow AI Hunter Detection Pipeline

> Operational guide for the detection ingestion → worker → persistence pipeline.
> Frontend, scanning, and UI are out of scope here.

---

## Phase 1 Completion Summary

**Phase 1 establishes a tenant-safe, multi-project-capable detection backend.**

### What Phase 1 includes

- `POST /ingest/event` + `GET /ingest/status/{job_id}` — full RQ worker pipeline (events → detection → findings → alerts)
- AI service signature detection via `dest_domain`/`tls_sni` matching
- Risk scoring, heuristic detection (high-volume upload threshold)
- Alerts auto-generated from detection findings
- MongoDB persistence across `events`, `detections`, `findings`, `alerts` collections
- `INGEST_API_KEYS` — project-bound API key model (each key maps to one project)
- All read/list endpoints are project-scoped for API-key callers
- JWT/Bearer auth retained for internal operator access

### Which endpoints are project-scoped

| Endpoint | API-key caller | JWT/Bearer caller |
|---|---|---|
| `POST /ingest/event` | project-bound (key must match `project` field) | — |
| `GET /ingest/status/{job_id}` | project-scoped (403 if job belongs to different project) | full access |
| `GET /api/alerts` | project-scoped | full access |
| `GET /api/devices` | project-scoped | full access |
| `GET /api/scans` | project-scoped | full access |
| `GET /api/scans/{scan_id}` | project-scoped | full access |
| `GET /api/dashboard/stats` | project-scoped metrics | full (global) metrics |
| `GET /api/policies` | project-scoped | full access |
| `POST /api/policies` | project-tagged on insert | full access (untagged) |

### Current image tags

| Tag | State | Commit |
|---|---|---|
| `shadow-ai-hunter_backend:phase1-final` | Phase 1 scoped backend | `e5b4a03` |
| `shadow-ai-hunter_backend:phase1-scoped` | Pre-policy-scope snapshot | `4b9a4b7` |
| `shadow-ai-hunter_backend:phase1-v1` | Phase 1 without tenant scoping | `0b4e1dc` |

Use `shadow-ai-hunter_backend:phase1-final` for all Phase 1 deployments.

### What Phase 1 does NOT include (known gaps)

- **Per-customer API key self-service** — keys are configured via `INGEST_API_KEYS` env var; no UI or API for customers to create/rotate keys
- **Usage metering / billing** — no `usage_records` collection or per-customer event metering
- **Alert notifications** — detections create alert records; no push to Slack, email, or webhook
- **Real policy enforcement** — `policy_enforcer.py` is a local stdout stub
- **Multi-project isolation enforcement** — device records must be tagged with project identity
- **Docker Hub push** — image push not yet configured
- **Customer-facing docs / onboarding** — no OpenAPI portal, no install guide

---

## Phase 2 Completion Summary

**Phase 2 adds API key self-service, usage metering, outbound alert notifications, and operator tooling.**

### What Phase 2 adds

#### MongoDB-backed API key store
- Keys stored in `api_keys` MongoDB collection (`_id`, `api_key`, `project_id`, `created_at`, `active`, `created_by`, optional `revoked_at`)
- In-process cache with 60s TTL — new keys are valid without service restart
- `INGEST_API_KEYS` env var still works as static fallback (backward compat)

#### Operator/admin endpoints (JWT analyst+ required)

| Method | Path | Description |
|---|---|---|
| `POST` | `/admin/api-keys` | Create a new API key for a project; returns plaintext key once |
| `GET` | `/admin/api-keys` | List all API keys (masked — only `key_prefix` exposed, never full key) |
| `DELETE` | `/admin/api-keys/{api_key}` | Soft-revoke a key (`active=false`); immediately invalidates cache |
| `GET` | `/api/usage` | Read `usage_records` for a project with optional `from_date`/`to_date` filter |

#### Alert operator endpoints (JWT analyst+ required)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/alerts/{alert_id}` | Single alert detail (includes notification status fields) |
| `PATCH` | `/api/alerts/{alert_id}` | Mark alert acknowledged/resolved; stores `updated_at` + `updated_by` |
| `POST` | `/api/alerts/{alert_id}/retry-notification` | Re-fire outbound webhook for a high/critical alert |

#### Alert notification system
- Outbound webhook POST to `ALERT_WEBHOOK_URL` env var (env-read at call time, no restart needed)
- Triggered only for `high` or `critical` severity alerts
- Compact JSON payload: `{title, severity, source_project, project_id, detection_id, created_at}`
- 10s timeout; all failures logged and swallowed — never blocks detection pipeline
- Delivery status persisted on every alert: `notification_attempted`, `notification_sent`, `notification_error`, `notification_last_attempt_at`
- `GET /api/alerts` supports `?notification_status=sent|failed|attempted|unattempted` filter
- `POST /api/alerts/{alert_id}/retry-notification` re-fires webhook and updates status

#### Usage metering
- `usage_records` collection: one doc per project per UTC day
- Document shape: `{project_id, date_bucket, events_ingested, requests_count, created_at, updated_at}`
- `date_bucket` is UTC midnight datetime; unique constraint on `(project_id, date_bucket)`
- Auto-upserted on every `POST /ingest/event` (atomic `$inc`; never blocks ingest)
- Read via `GET /api/usage?project_id=X&from_date=YYYY-MM-DD&to_date=YYYY-MM-DD`

### Current image tags

| Tag | State | Commit |
|---|---|---|
| `shadow-ai-hunter_backend:p2s12` | Phase 2 Step 12 build | `658fc89` (latest Phase 2) |
| `shadow-ai-hunter_backend:phase1-final` | Phase 1 scoped backend | `e5b4a03` |

### What Phase 2 does NOT include (known gaps)

- **Docker Hub / GHCR push** — image must be built locally; no registry credentials configured
- **Per-project webhook URLs** — single global `ALERT_WEBHOOK_URL` for all projects
- **Alert retry queue** — no automatic retry with backoff; only manual retry via endpoint
- **Slack/email integrations** — only generic webhook POST; no Slack/email-specific formatting
- **Rate limiting / quotas** — no enforcement of per-project limits based on usage_records
- **Audit logging** — no `audit_log` collection tracking who called which endpoint
- **Customer-facing key management UI** — only operator/admin access via JWT
- **Per-customer billing calculation** — usage_records are written but no invoice/pricing logic
- **Real policy enforcement** — `policy_enforcer.py` is still a local stdout stub

---

## API Key Configuration

### Phase 1 style (static env var)

```bash
INGEST_API_KEYS=project-elephant:key-alpha,project-bison:key-beta
```

### Phase 2 style (MongoDB-backed, hot-reloadable)

Keys are stored in the `api_keys` MongoDB collection and validated against it at runtime.
Static env fallback still works for keys defined in `INGEST_API_KEYS`.

Operator creates a key via:

```bash
# Create a new key for a project (JWT required)
curl -X POST "http://localhost:8001/admin/api-keys?project_id=project-fox" \
  -H "Authorization: Bearer <analyst-jwt>"
# Response: {"api_key": "<plaintext-key>", "project_id": "project-fox", ...}
# Store the key — it cannot be retrieved again
```

Operator lists keys:

```bash
curl "http://localhost:8001/admin/api-keys" \
  -H "Authorization: Bearer <analyst-jwt>"
# Returns: {api_keys: [{key_prefix: "abc123...", project_id: "...", active: true, ...}]}
# Note: full plaintext key is NEVER returned after creation
```

Operator revokes a key:

```bash
curl -X DELETE "http://localhost:8001/admin/api-keys/<full-api-key>" \
  -H "Authorization: Bearer <analyst-jwt>"
# Response: {"message": "API key revoked", "api_key": "abc123..."}
# Revoked key immediately fails X-API-Key validation
```

---

## Startup

```bash
# Bring up the full backend slice
docker compose up -d mongodb redis backend worker

# Verify all containers are running
docker compose ps
```

### Verifying the worker is active

```bash
docker compose logs worker | grep "Starting RQ worker"
# Expected: "Starting RQ worker on queue: detection"
```

### Dev mode (no worker, fallback execution inline)

```bash
ENABLE_FALLBACK=true docker compose up -d mongodb redis backend
```

> **⚠️ `ENABLE_FALLBACK` is dev-only and defaults to `false`.**
> In production the worker container must be running — without it, events are
> ingested but detection does not execute (logged explicitly at `ERROR` level).

---

## Sending a Test Event

```bash
curl -X POST http://localhost:8001/ingest/event \
  -H "Content-Type: application/json" \
  -H "X-API-Key: key-alpha" \
  -d '{
    "project": "project-elephant",
    "events": [
      {
        "dest_domain": "api.openai.com",
        "tls_sni": "api.openai.com",
        "device_ip": "10.0.1.5",
        "bytes_out": 4096
      }
    ]
  }'
```

Response:

```json
{
  "accepted": true,
  "project": "project-elephant",
  "events_ingested": 1,
  "job_id": "ingest-<uuid>",
  "event_ids": ["evt-<uuid>"]
}
```

Save the `job_id` for the next step.

---

## Polling Detection Status

```bash
curl http://localhost:8001/ingest/status/ingest-<uuid> \
  -H "X-API-Key: key-alpha"
```

Response when complete:

```json
{
  "job_id": "ingest-<uuid>",
  "status": "completed",
  "source_project": "project-elephant",
  "findings_count": 2,
  "risk_score": 0.38,
  "created_at": "2026-04-10T10:47:00.000Z",
  "completed_at": "2026-04-10T10:47:02.000Z"
}
```

`status` values: `queued` → `running` → `completed` | `failed` | `unknown`

---

## Inspecting Persisted Data in MongoDB

```bash
docker compose exec mongodb mongosh \
  -u admin -p changeme \
  --authenticationDatabase admin shadow_ai_hunter
```

Inside mongosh:

```js
// Show all detection records
db.detections.find().sort({created_at: -1}).limit(5).pretty()

// Show findings for a specific detection
db.findings.find({detection_id: "ingest-<uuid>"}).pretty()

// Show alerts for a project
db.alerts.find({source_project: "project-elephant"}).sort({created_at: -1}).limit(5).pretty()

// Show ingested events for a project
db.events.find({source_project: "project-elephant"}).sort({created_at: -1}).limit(5).pretty()

// Count pending (undetected) events — indicates detection lag
db.events.countDocuments({detection_status: "pending"})

// Show usage records for a project
db.usage_records.find({project_id: "project-elephant"}).sort({date_bucket: 1}).pretty()

// Show API keys (masked — full key is not stored)
db.api_keys.find({}, {api_key: 0}).pretty()
```

---

## Key Endpoints Summary

| Method | Path | API-key scope | JWT scope |
|---|---|---|---|
| `POST` | `/ingest/event` | project-bound | — |
| `GET` | `/ingest/status/{job_id}` | project-scoped | full access |
| `GET` | `/api/health` | none | none |
| `GET` | `/api/dashboard/stats` | scoped metrics | full (global) metrics |
| `GET` | `/api/alerts` | project-scoped | full access |
| `GET` | `/api/alerts/{alert_id}` | project-scoped | full access |
| `PATCH` | `/api/alerts/{alert_id}` | — | JWT analyst+ only |
| `POST` | `/api/alerts/{alert_id}/retry-notification` | — | JWT analyst+ only |
| `GET` | `/api/devices` | project-scoped | full access |
| `GET` | `/api/scans` | project-scoped | full access |
| `GET` | `/api/scans/{scan_id}` | project-scoped | full access |
| `GET` | `/api/policies` | project-scoped | full access |
| `POST` | `/api/policies` | project-tagged | full access (untagged) |
| `POST` | `/api/scan` | — | JWT (analyst+) |
| `POST` | `/api/telemetry/import` | — | JWT (admin) |
| `GET` | `/api/usage` | — | JWT analyst+ only |
| `POST` | `/admin/api-keys` | — | JWT analyst+ only |
| `GET` | `/admin/api-keys` | — | JWT analyst+ only |
| `DELETE` | `/admin/api-keys/{api_key}` | — | JWT analyst+ only |

---

## Restarting the Worker

```bash
# Restart just the worker (e.g., after code changes)
docker compose restart worker

# Tail worker logs
docker compose logs -f worker
```

Jobs that were queued before a worker restart are not lost — RQ retains them in Redis and they will be processed when the worker comes back up.
