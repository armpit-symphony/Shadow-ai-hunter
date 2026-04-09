# Shadow AI Hunter — System Map
*v2.0.0 | Agentic Security Audit Platform*

---

## 1. Services

| Service | Docker Container | Port | Role |
|---------|----------------|------|------|
| Frontend | `shadow-ai-hunter_frontend` | 3000 (HTTP) → served via Nginx | React 18 SPA dashboard |
| Backend API | `shadow-ai-hunter_backend` | 8001 | FastAPI REST + WebSocket |
| Nginx | `shadow-ai-hunter_nginx` | 80/443 | Reverse proxy, SSL termination |
| MongoDB | `shadow-ai-hunter_mongodb` | 27017 | Primary data store |
| Redis | `shadow-ai-hunter_redis` | 6379 | RQ queue backend, pub/sub |
| Worker: scanner | (in backend container) | — | Network host discovery + AI port fingerprinting |
| Worker: detector | (in backend container) | — | Signature + heuristic AI usage detection |
| Worker: telemetry | (in backend container) | — | DNS/proxy log normalization |
| Worker: enrichment | (in backend container) | — | Asset criticality + policy evaluation |
| Worker: report | (in backend container) | — | JSON/PDF report generation |

---

## 2. Data Flow

### 2a. Network Scan Path
```
User → POST /api/scans (JWT) → backend/server.py
  → scan record created in MongoDB (scans collection)
  → job enqueued to Redis queue 'scans'
  → scanner_worker.network_discovery_scan() picks up job
    → nmap / TCP connect scan of target CIDR
    → devices discovered → stored in MongoDB (devices collection)
    → alerts created if AI services found
    → scan record updated to 'completed'
```

### 2b. Telemetry Detection Path
```
Log sources (DNS/proxy) → telemetry_worker.ingest_telemetry()
  → normalized events stored in MongoDB (events collection)
  → job enqueued to Redis queue 'detection'
  → detector_worker.run_detection() picks up job
    → signature match against AI_SERVICE_SIGNATURES DB
    → heuristic rules (volume, off-hours, user-agent)
    → findings stored in MongoDB (findings collection)
    → alerts created if risk_score >= 0.5
    → scan record updated to 'completed'
```

### 2c. Enrichment Path
```
scanner / detector output → enrichment_worker.enrich_scan()
  → asset criticality lookup per device
  → active policies evaluated against device/services
  → risk score re-weighted by criticality
  → policy-violation alerts created if matches found
```

### 2d. Reporting Path
```
User → POST /api/reports (JWT) → report_worker.create_report()
  → reads scan record + findings from MongoDB
  → generates JSON report (with integrity hash)
  → optionally generates PDF via fpdf2
  → report stored in MongoDB (reports collection)
  → optionally exported to SIEM webhook
```

---

## 3. Queue Usage (Redis / RQ)

| Queue | Workers | Jobs |
|-------|---------|------|
| `scans` | scanner_worker | `network_discovery_scan(scan_id, network_range)` |
| `telemetry` | telemetry_worker | `ingest_telemetry(scan_id, log_entries)` |
| `detection` | detector_worker | `run_detection(scan_id, events)` |
| `enrichment` | enrichment_worker | `enrich_scan(scan_id)` |
| `reports` | report_worker | `create_report(scan_id, scan_data, findings, format)` |

**Redis also used for:** WebSocket pub/sub (`ws_events` channel) for real-time dashboard updates.

---

## 4. Where Scans Are Triggered and Processed

1. **Trigger:** `POST /api/scans` with `network_range` in body → MongoDB `scans` doc created → RQ job enqueued
2. **Process:** Worker polls Redis `scans` queue → `network_discovery_scan()` runs → results persisted
3. **Progress:** Real-time via WebSocket (`ws_events` channel) + MongoDB `ws_events` collection
4. **Completion:** Scan doc updated to `completed` → enrichment job queued automatically

---

## 5. Where Results Are Stored (MongoDB Collections)

| Collection | Contents |
|-----------|----------|
| `users` | Username, hashed password, role, disabled |
| `scans` | Job record: network_range, status, timestamps, device/finding counts |
| `devices` | IP, hostname, open_ports, AI services, risk_score, scan_id, last_seen |
| `events` | Normalized telemetry: source, dest_domain, bytes, user_agent, etc. |
| `findings` | Detection findings per event |
| `alerts` | title, severity, device_ip, evidence, scan_id, resolved flag |
| `reports` | report_id, scan_id, JSON content, report format |
| `policies` | name, conditions, actions, enabled flag |
| `lists` | Allowlist/denylist domain entries |
| `baselines` | Per-segment baseline for heuristic detection |
| `ws_events` | In-memory WebSocket events (TTL: 6h) |
| `audit_logs` | Auth events (TTL: 365 days) |
| `siem_deliveries` | SIEM webhook delivery status |

---

## 6. Key API Routes

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/auth/login` | None | JWT login |
| POST | `/api/auth/register` | None | User registration |
| POST | `/api/auth/refresh` | Refresh cookie | Refresh access token |
| POST | `/api/auth/logout` | JWT | Logout + clear refresh token |
| GET | `/api/users/me` | JWT | Current user profile |
| GET | `/api/scans` | JWT | List all scans |
| POST | `/api/scans` | JWT+analyst | Create + start network scan |
| GET | `/api/scans/{scan_id}` | JWT | Get scan details |
| DELETE | `/api/scans/{scan_id}` | JWT+admin | Cancel/delete scan |
| GET | `/api/scans/{scan_id}/devices` | JWT | Devices from a scan |
| GET | `/api/alerts` | JWT | List alerts |
| PUT | `/api/alerts/{alert_id}` | JWT | Update alert (resolve) |
| POST | `/api/policies` | JWT+admin | Create policy |
| GET | `/api/policies` | JWT | List policies |
| POST | `/api/reports` | JWT | Generate report |
| GET | `/api/reports/{report_id}` | JWT | Get report |
| GET | `/api/ai-services` | JWT | List known AI service signatures |
| GET | `/api/health` | None | Health check |
| GET | `/api/demo/populate` | None | Load demo data (DEV ONLY) |

---

## 7. WebSocket

- **Endpoint:** `ws://host/api/ws?token=<jwt>`
- **Auth:** JWT validated on connect
- **Channel:** `ws_events` published via Redis pub/sub
- **Events emitted:** `scan_started`, `scan_progress`, `scan_completed`, `scan_failed`, `detection_completed`, `alert_created`

---

## 8. Configuration (Environment Variables)

Key vars (defaults = insecure):

| Variable | Default | Production Requirement |
|---------|---------|----------------------|
| `JWT_SECRET_KEY` | `"your-jwt-secret-change-in-production"` | MUST set random 256-bit secret |
| `MONGO_URL` | `mongodb://localhost:27017/shadow_ai_hunter` | Secured, no expose |
| `REDIS_URL` | `redis://localhost:6379/0` | Secured, no expose |
| `SUPER_ADMIN_USERS` | `"admin"` | Change default admin username |
| `REPORT_MASK_PII` | `"false"` | Set `"true"` for GDPR compliance |
| `SCAN_MAX_HOSTS` | `"254"` | Reduce for large scans |
| `SEGMENT_MAP` | (none) | Set for multi-segment baselines |
