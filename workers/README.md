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

These are out of scope for Phase 1 and must be addressed before the product is publicly sellable:

- **Multi-project isolation enforcement** — `source_project`/`project_id` must be added to device records created by the scanner worker
- **Per-customer API key self-service** — keys are configured via `INGEST_API_KEYS` env var; no UI or API for customers to create/rotate keys
- **Usage metering / billing** — no `usage_records` collection or per-customer event metering
- **Audit logging** — no `audit_log` collection tracking access history
- **Customer-facing docs / onboarding** — no OpenAPI portal, no Postman collection, no install guide
- **Alert notifications** — detections create alert records; no push to Slack, email, or webhook
- **Real policy enforcement** — `policy_enforcer.py` is a local stdout stub; no cloud firewall integration (AWS SG, GCP Firewall, Cloudflare)
- **AI_SERVICES map extensibility** — 13 hardcoded domains; customers cannot add custom signatures
- **Docker Hub push** — image push is not yet configured; operators must build locally

---

## API Key Configuration

`POST /ingest/event` and `GET /ingest/status/{job_id}` both require a valid `X-API-Key` header.

Set `INGEST_API_KEYS` as `project-id:key` pairs, comma-separated:

```bash
# docker-compose.env or .env
INGEST_API_KEYS=project-elephant:key-alpha,project-bison:key-beta,project-capybara:key-gamma
```

- Each key maps to **exactly one** project — cross-project access is rejected with 403
- `POST /ingest/event`: the request `project` field must match the key's bound project
- `GET /ingest/status/{job_id}`: returns 403 if the job's `source_project` does not match the key's bound project
- Jobs with no `source_project` (pre-change records) are accessible with any valid key (backward compat)

> **No keys configured = endpoint returns 503** — fail-closed to prevent accidental open access.

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
| `GET` | `/api/devices` | project-scoped | full access |
| `GET` | `/api/scans` | project-scoped | full access |
| `GET` | `/api/scans/{scan_id}` | project-scoped | full access |
| `GET` | `/api/policies` | project-scoped | full access |
| `POST` | `/api/policies` | project-tagged | full access (untagged) |
| `POST` | `/api/scan` | — | JWT (analyst+) |
| `POST` | `/api/telemetry/import` | — | JWT (admin) |

---

## Restarting the Worker

```bash
# Restart just the worker (e.g., after code changes)
docker compose restart worker

# Tail worker logs
docker compose logs -f worker
```

Jobs that were queued before a worker restart are not lost — RQ retains them in Redis and they will be processed when the worker comes back up.
