# Shadow AI Hunter

> Detect, monitor, and manage unauthorized AI tool usage across enterprise network infrastructure.

**Status**: Active development — **Phase 2 complete**. Backend is service-ready for self-hosted deployment.

---

## What It Does

Shadow AI Hunter watches your network for connections to AI services (OpenAI, Anthropic, Hugging Face, etc.) that shouldn't be there. It ingests network telemetry events, runs signature-based and heuristic detection, generates alerts, and can notify operators via webhook when high/critical incidents are found.

It is a **multi-tenant backend** — each customer/project gets isolated API keys, scoped data access, and tracked usage.

---

## Architecture

```
Ingest (POST /ingest/event)
    → events collection
    → RQ worker (detector)
        → detections + findings collections
        → alerts collection
        → webhook notification (high/critical)
    → usage_records collection
```

| Service | Port | Purpose |
|---|---|---|
| MongoDB | 27017 | All persistence |
| Redis | 6379 | RQ job queue |
| Backend | 8001 | FastAPI server |
| Worker | — | Detection queue consumer |

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/armpit-symphony/Shadow-ai-hunter.git
cd Shadow-ai-hunter

# 2. Configure environment
cp backend/.env.example backend/.env
# Edit backend/.env — set MONGO_URL, REDIS_URL, JWT_SECRET_KEY

# 3. Build and start
docker compose up -d mongodb redis backend worker

# 4. Create an admin JWT token (first-time)
# Use the /auth/login endpoint with default credentials (see workers/README.md)

# 5. Create a project API key
curl -X POST "http://localhost:8001/admin/api-keys?project_id=my-project" \
  -H "Authorization: Bearer <admin-jwt>"

# 6. Send telemetry events
curl -X POST http://localhost:8001/ingest/event \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <your-api-key>" \
  -d '{
    "project": "my-project",
    "events": [
      {"device_ip": "10.0.1.5", "dest_domain": "api.openai.com", "tls_sni": "api.openai.com"}
    ]
  }'
```

See [workers/README.md](workers/README.md) for full operational documentation.

---

## Current Capabilities

### Detection
- Signature detection via `dest_domain` + `tls_sni` field matching against 13 known AI service domains
- Heuristic detection: high-volume upload threshold
- Risk scoring per scan
- RQ worker pipeline: events → detection → findings → alerts

### Multi-Tenant Isolation
- Project-scoped API keys (MongoDB-backed, hot-reloadable)
- Project-scoped reads on all data endpoints
- API-key callers see only their project's data
- JWT/Bearer callers have full internal access

### Alerting & Notifications
- Auto-generated alerts for high/critical detections
- Outbound webhook notifications (`ALERT_WEBHOOK_URL` env var)
- Notification delivery status tracked on every alert
- Manual retry endpoint for failed webhooks
- Filter alerts by notification delivery state

### Usage Metering
- Per-project daily event counts (`usage_records` collection)
- Atomic upsert on every ingest — no counting overhead
- Read via operator API

### Operator API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/ingest/event` | API key | Ingest telemetry events |
| `GET` | `/ingest/status/{job_id}` | API key / JWT | Check detection job status |
| `GET` | `/api/alerts` | API key / JWT | List alerts |
| `GET` | `/api/alerts/{alert_id}` | API key / JWT | Single alert detail |
| `PATCH` | `/api/alerts/{alert_id}` | JWT | Acknowledge / resolve alert |
| `POST` | `/api/alerts/{alert_id}/retry-notification` | JWT | Re-fire webhook for alert |
| `GET` | `/api/scans` | API key / JWT | List scans |
| `GET` | `/api/devices` | API key / JWT | List devices |
| `GET` | `/api/dashboard/stats` | API key / JWT | Dashboard metrics |
| `GET` | `/api/policies` | API key / JWT | List policies |
| `POST` | `/api/policies` | API key / JWT | Create policy |
| `GET` | `/api/usage` | JWT | Read usage records |
| `POST` | `/admin/api-keys` | JWT | Create API key |
| `GET` | `/admin/api-keys` | JWT | List API keys (masked) |
| `DELETE` | `/admin/api-keys/{key}` | JWT | Revoke API key |

---

## Known Gaps (Not Yet Implemented)

These features are planned but not yet built:

- **Policy enforcement stub** — `policy_enforcer.py` is a stdout stub; no actual firewall integration
- **Per-project webhook URLs** — single global `ALERT_WEBHOOK_URL` only
- **Automatic webhook retry** — only manual retry via endpoint
- **Slack/email formatting** — webhook payload is generic JSON only
- **Rate limiting / quotas** — no enforcement based on `usage_records`
- **Audit logging** — no `audit_log` collection
- **Customer key self-service UI** — operator creates keys via API only
- **Device project tagging** — device records must be populated with project identity
- **Docker Hub push** — image must be built locally
- **OpenAPI docs** — not served at runtime
- **AI_SERVICES extensibility** — 13 domains hardcoded; no customer-configurable signatures

---

## Project Structure

```
Shadow-ai-hunter/
├── backend/
│   ├── server.py          # FastAPI app + routes
│   ├── auth.py            # JWT auth + RBAC
│   ├── auth_routes.py    # /auth/* routes
│   ├── workers/
│   │   ├── detector_worker.py   # Detection pipeline
│   │   ├── models.py            # MongoDB schemas + helpers
│   │   ├── notifications.py      # Webhook sender
│   │   ├── api_keys.py          # MongoDB-backed API key store
│   │   └── queue.py             # RQ queue config
│   └── Dockerfile
├── frontend/              # React dashboard (separate)
├── docker-compose.yml
└── workers/
    └── README.md         # Full operational runbook
```

---

## License

MIT
