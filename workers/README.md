# Backend Runbook — Shadow AI Hunter Detection Pipeline

> Operational guide for the detection ingestion → worker → persistence pipeline.
> Frontend, scanning, and UI are out of scope here.

---

## Required Services

| Service | Port | Purpose |
|---------|------|---------|
| `mongodb` | 27017 | Event + detection + finding storage |
| `redis` | 6379 | RQ job queue broker |
| `backend` | 8001 | FastAPI server (`/ingest/event`, `/ingest/status`) |
| `worker` | — | RQ worker consuming the `detection` queue |

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
  -d '{
    "project": "sparkbot",
    "events": [
      {
        "dest_domain": "openai.com",
        "src_ip": "10.0.1.5",
        "bytes_out": 4096
      }
    ]
  }'
```

Response:

```json
{
  "accepted": true,
  "project": "sparkbot",
  "events_ingested": 1,
  "job_id": "ingest-<uuid>",
  "event_ids": ["evt-<uuid>"]
}
```

Save the `job_id` for the next step.

---

## Polling Detection Status

```bash
curl http://localhost:8001/ingest/status/ingest-<uuid>
```

Response when complete:

```json
{
  "job_id": "ingest-<uuid>",
  "status": "completed",
  "source_project": "sparkbot",
  "findings_count": 1,
  "risk_score": 0.475,
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

// Show ingested events for a project
db.events.find({source_project: "sparkbot"}).sort({ingested_at: -1}).limit(5).pretty()

// Count pending (undetected) events — indicates detection lag
db.events.countDocuments({detection_status: "pending"})
```

---

## Key Endpoints Summary

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `POST` | `/ingest/event` | none | Ingest telemetry events |
| `GET` | `/ingest/status/{job_id}` | none | Poll detection job status |
| `GET` | `/api/health` | none | Backend liveness check |
| `GET` | `/api/dashboard/stats` | JWT (viewer+) | Dashboard metrics |
| `POST` | `/api/scan` | JWT (analyst+) | Start network scan |
| `POST` | `/api/telemetry/import` | JWT (admin) | Bulk telemetry import |

---

## Restarting the Worker

```bash
# Restart just the worker (e.g., after code changes)
docker compose restart worker

# Tail worker logs
docker compose logs -f worker
```

Jobs that were queued before a worker restart are not lost — RQ retains them in Redis and they will be processed when the worker comes back up.
